package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type Server struct {
	Addr        string
	Repo        ports.DNSRepository
	Cache       *DNSCache
	Redis       *RedisCache
	WorkerCount int
	udpQueue    chan udpTask
	Logger      *slog.Logger
	queryFn     func(server string, name string, qtype packet.QueryType) (*packet.DnsPacket, error)
	limiter     *rateLimiter
	TsigKeys    map[string][]byte
}

type udpTask struct {
	addr net.Addr
	data []byte
	conn net.PacketConn
}

func NewServer(addr string, repo ports.DNSRepository, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		Addr:        addr,
		Repo:        repo,
		Cache:       NewDNSCache(),
		WorkerCount: runtime.NumCPU() * 8,
		udpQueue:    make(chan udpTask, 10000),
		Logger:      logger,
		limiter:     newRateLimiter(200000, 100000),
		TsigKeys:    make(map[string][]byte),
	}
	s.queryFn = s.sendQuery

	// Periodic cleanup of rate limiter buckets
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			s.limiter.Cleanup()
		}
	}()

	return s
}

func (s *Server) Run() error {
	s.Logger.Info("starting parallel server", "addr", s.Addr, "listeners", runtime.NumCPU())

	// 1. Parallel UDP Listeners using SO_REUSEPORT
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
			})
		},
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go func(id int) {
			conn, err := lc.ListenPacket(context.Background(), "udp", s.Addr)
			if err != nil {
				s.Logger.Error("failed to start UDP listener", "id", id, "error", err)
				return
			}
			defer conn.Close()

			for {
				buf := make([]byte, 512)
				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					continue
				}
				data := make([]byte, n)
				copy(data, buf[:n])
				s.udpQueue <- udpTask{addr: addr, data: data, conn: conn}
			}
		}(i)
	}

	// 2. Start UDP Workers
	for i := 0; i < s.WorkerCount; i++ {
		go s.udpWorker()
	}

	// 3. Start TCP Listener
	tcpListener, err := lc.Listen(context.Background(), "tcp", s.Addr)
	if err != nil {
		return err
	}
	defer tcpListener.Close()

	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPConnection(conn)
	}
}

func (s *Server) udpWorker() {
	for task := range s.udpQueue {
		s.handleUDPConnection(task.conn, task.addr, task.data)
	}
}

func (s *Server) handleUDPConnection(pc net.PacketConn, addr net.Addr, data []byte) {
	s.handlePacket(data, addr, func(resp []byte) error {
		_, err := pc.WriteTo(resp, addr)
		return err
	})
}

func (s *Server) handleTCPConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("New TCP connection from %s\n", conn.RemoteAddr())

	for {
		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		_, err := conn.Read(lenBuf)
		if err != nil {
			return
		}
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])

		// Read actual packet
		data := make([]byte, packetLen)
		_, err = conn.Read(data)
		if err != nil {
			return
		}

		err = s.handlePacket(data, conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp))
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, err := conn.Write(fullResp)
			return err
		})

		if err != nil {
			s.Logger.Error("TCP processing error", "error", err)
			return
		}
	}
}

func (s *Server) handlePacket(data []byte, srcAddr net.Addr, sendFn func([]byte) error) error {
	start := time.Now()
	clientIP, _, _ := net.SplitHostPort(srcAddr.String())
	
	// Create a contextual logger for this request
	logger := s.Logger.With("client_ip", clientIP)

	// --- Rate Limiting ---
	if !s.limiter.Allow(clientIP) {
		logger.Warn("rate limit exceeded", "ip", clientIP)
		return nil 
	}

	// 1. Parse Request
	reqBuffer := packet.GetBuffer()
	defer packet.PutBuffer(reqBuffer)
	reqBuffer.Load(data)

	request := packet.NewDnsPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		logger.Error("failed to parse incoming packet", "error", err)
		return err
	}

	// --- TSIG Verification ---
	var authenticatedKey string
	if len(request.Resources) > 0 {
		lastRec := request.Resources[len(request.Resources)-1]
		if lastRec.Type == packet.TSIG {
			secret, exists := s.TsigKeys[lastRec.Name]
			if !exists {
				logger.Warn("unknown TSIG key", "key", lastRec.Name)
			} else {
				if err := request.VerifyTSIG(data, lastRec.Name, secret); err != nil {
					logger.Error("TSIG verification failed", "error", err, "key", lastRec.Name)
					return err
				}
				authenticatedKey = lastRec.Name
				logger.Info("authenticated DNS request", "key", authenticatedKey)
			}
		}
	}

	var queryName string
	var queryType packet.QueryType
	if len(request.Questions) > 0 {
		queryName = request.Questions[0].Name
		queryType = request.Questions[0].QType
	}

	// Extract EDNS info
	var maxUDPSize uint16 = 512
	hasEDNS := false
	for _, res := range request.Resources {
		if res.Type == packet.OPT {
			maxUDPSize = res.UDPPayloadSize
			hasEDNS = true
			if maxUDPSize < 512 {
				maxUDPSize = 512
			}
		}
	}

	// 2. Check TIERED CACHE
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)
		
		// Tier 1: In-Memory
		if cachedData, found := s.Cache.Get(cacheKey); found {
			if len(cachedData) >= 2 {
				cachedData[0] = byte(request.Header.ID >> 8)
				cachedData[1] = byte(request.Header.ID & 0xFF)
			}
			err := sendFn(cachedData)
			logger.Info("dns query processed", "name", queryName, "type", queryType, "cache", "l1-hit", "latency_ms", time.Since(start).Milliseconds())
			return err
		}

		// Tier 2: Redis
		if s.Redis != nil {
			if cachedData, found := s.Redis.Get(context.Background(), cacheKey); found {
				if len(cachedData) >= 2 {
					cachedData[0] = byte(request.Header.ID >> 8)
					cachedData[1] = byte(request.Header.ID & 0xFF)
				}
				// Populate L1 from L2
				s.Cache.Set(cacheKey, cachedData, 60*time.Second)
				err := sendFn(cachedData)
				logger.Info("dns query processed", "name", queryName, "type", queryType, "cache", "l2-hit", "latency_ms", time.Since(start).Milliseconds())
				return err
			}
		}
	}

	// 3. Prepare Response
	response := packet.NewDnsPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = request.Header.Opcode
	response.Header.RecursionDesired = request.Header.RecursionDesired
	response.Header.RecursionAvailable = false
	response.Header.AuthoritativeAnswer = true
	response.Header.ResCode = 0

	if hasEDNS {
		response.Resources = append(response.Resources, packet.DnsRecord{
			Type:           packet.OPT,
			UDPPayloadSize: 1232, 
		})
	}

	// 4. Resolve using Repository
	var minTTL uint32 = 300
	source := "local"
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		response.Questions = append(response.Questions, q)

		// --- Fast Path for A Records ---
		if q.QType == packet.A {
			ips, err := s.Repo.GetIPsForName(context.Background(), q.Name, clientIP)
			if err == nil && len(ips) > 0 {
				source = "local-fast"
				for _, ipStr := range ips {
					response.Answers = append(response.Answers, packet.DnsRecord{
						Name:  q.Name,
						Type:  packet.A,
						Class: 1,
						TTL:   minTTL,
						IP:    net.ParseIP(ipStr),
					})
				}
				goto SERIALIZE
			}
		}

		var domainType domain.RecordType
		switch q.QType {
		case packet.A: domainType = domain.TypeA
		case packet.AAAA: domainType = domain.TypeAAAA
		case packet.CNAME: domainType = domain.TypeCNAME
		case packet.NS: domainType = domain.TypeNS
		}

		records, err := s.Repo.GetRecords(context.Background(), q.Name, domainType, clientIP)
		if err != nil {
			logger.Error("repository lookup failed", "error", err, "name", q.Name)
			response.Header.ResCode = 2 // SERVFAIL
		} else if len(records) > 0 {
			for i, rec := range records {
				pRec, err := repository.ConvertDomainToPacketRecord(rec)
				if err == nil {
					response.Answers = append(response.Answers, pRec)
					if i == 0 || pRec.TTL < minTTL {
						minTTL = pRec.TTL
					}
				}
			}
		} else if request.Header.RecursionDesired {
			source = "recursive"
			recursiveResp, err := s.resolveRecursive(q.Name, q.QType)
			if err == nil {
				response.Answers = recursiveResp.Answers
				response.Authorities = recursiveResp.Authorities
				response.Header.ResCode = recursiveResp.Header.ResCode
			} else {
				logger.Error("recursive resolution failed", "error", err, "name", q.Name)
				response.Header.ResCode = 2 // SERVFAIL
			}
		} else {
			response.Header.ResCode = 3 // NXDOMAIN
			minTTL = 60 // NXDOMAIN TTL (Negative Caching RFC 2308)
		}
	} else {
		response.Header.ResCode = 4 // FORMERR
	}

SERIALIZE:
	// 5. Serialize and Handle Truncation
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	
	if err := response.Write(resBuffer); err != nil {
		logger.Error("serialization failed", "error", err)
		return err
	}

	// Sign response if requested
	if authenticatedKey != "" {
		s.Logger.Info("signing response with TSIG", "key", authenticatedKey)
		secret := s.TsigKeys[authenticatedKey]
		response.SignTSIG(resBuffer, authenticatedKey, secret)
	}

	if resBuffer.Position() > int(maxUDPSize) {
		response.Header.TruncatedMessage = true
		response.Answers = nil
		response.Authorities = nil
		resBuffer.Reset()
		response.Write(resBuffer)
	}

	resData := resBuffer.Buf[:resBuffer.Position()]

	// 6. Cache successful response (including NXDOMAIN)
	if len(request.Questions) > 0 && (response.Header.ResCode == 0 || response.Header.ResCode == 3) {
		q := request.Questions[0]
		cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)
		cacheData := make([]byte, len(resData))
		copy(cacheData, resData)
		
		// Populate L1 and L2
		s.Cache.Set(cacheKey, cacheData, time.Duration(minTTL)*time.Second)
		if s.Redis != nil {
			s.Redis.Set(context.Background(), cacheKey, cacheData, time.Duration(minTTL)*time.Second)
		}
	}

	// 7. Send Back
	err := sendFn(resData)
	logger.Info("dns query processed",
		"name", queryName,
		"type", queryType,
		"rcode", response.Header.ResCode,
		"cache", "miss",
		"source", source,
		"latency_ms", time.Since(start).Milliseconds(),
		"authenticated", authenticatedKey != "",
	)
	return err
}
