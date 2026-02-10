package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
)

type Server struct {
	Addr        string
	Repo        ports.DNSRepository
	Cache       *DNSCache
	WorkerCount int
	udpQueue    chan udpTask
	Logger      *slog.Logger
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
	return &Server{
		Addr:        addr,
		Repo:        repo,
		Cache:       NewDNSCache(),
		WorkerCount: 10,
		udpQueue:    make(chan udpTask, 1000),
		Logger:      logger,
	}
}

func (s *Server) Run() error {
	fmt.Printf("Attempting to listen on %s (UDP/TCP)...\n", s.Addr)

	// UDP
	udpAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Printf("Failed to listen UDP: %v\n", err)
		return err
	}
	defer udpConn.Close()

	// TCP
	tcpListener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		fmt.Printf("Failed to listen TCP: %v\n", err)
		return err
	}
	defer tcpListener.Close()

	fmt.Println("DNS Server successfully listening on", s.Addr, "(UDP and TCP)...")

	// Start UDP Workers
	for i := 0; i < s.WorkerCount; i++ {
		go s.udpWorker()
	}

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				fmt.Println("TCP Accept error:", err)
				continue
			}
			go s.handleTCPConnection(conn)
		}
	}()

	for {
		buf := make([]byte, 512)
		n, addr, err := udpConn.ReadFrom(buf)
		if err != nil {
			fmt.Println("UDP Read error:", err)
			continue
		}

		// Send to worker pool
		data := make([]byte, n)
		copy(data, buf[:n])
		s.udpQueue <- udpTask{addr: addr, data: data, conn: udpConn}
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
	// Extract IP for Split-Horizon
	clientIP, _, _ := net.SplitHostPort(srcAddr.String())
	// 1. Parse Request
	reqBuffer := packet.NewBytePacketBuffer()
	copy(reqBuffer.Buf, data)

	request := packet.NewDnsPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		s.Logger.Error("failed to parse packet", "error", err)
		return err
	}

	var queryName string
	var queryType packet.QueryType
	if len(request.Questions) > 0 {
		queryName = request.Questions[0].Name
		queryType = request.Questions[0].QType
	}

	// Extract EDNS info if present
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

	// 2. Check Cache
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)
		if cachedData, found := s.Cache.Get(cacheKey); found {
			// Need to rewrite the transaction ID from the request into the cached response
			if len(cachedData) >= 2 {
				cachedData[0] = byte(request.Header.ID >> 8)
				cachedData[1] = byte(request.Header.ID & 0xFF)
			}
			err := sendFn(cachedData)
			s.Logger.Info("dns query",
				"name", queryName,
				"type", queryType,
				"cache", "hit",
				"latency", time.Since(start),
			)
			return err
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

	// Add OPT record to response if client sent one
	if hasEDNS {
		response.Resources = append(response.Resources, packet.DnsRecord{
			Type:           packet.OPT,
			UDPPayloadSize: 1232, // Signal that we support up to 1232 bytes
		})
	}

	// 4. Resolve using Repository
	var minTTL uint32 = 300
	if len(request.Questions) > 0 {
		q := request.Questions[0]
		response.Questions = append(response.Questions, q)

		var domainType domain.RecordType
		switch q.QType {
		case packet.A: domainType = domain.TypeA
		case packet.AAAA: domainType = domain.TypeAAAA
		case packet.CNAME: domainType = domain.TypeCNAME
		case packet.NS: domainType = domain.TypeNS
		}

		records, err := s.Repo.GetRecords(context.Background(), q.Name, domainType, clientIP)
		if err != nil {
			s.Logger.Error("repository error", "error", err, "name", q.Name)
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
			// RECURSIVE LOOKUP
			recursiveResp, err := s.resolveRecursive(q.Name, q.QType)
			if err == nil {
				response.Answers = recursiveResp.Answers
				response.Authorities = recursiveResp.Authorities
				// If recursive result had OPT, it might conflict with ours, 
				// but for now we just append or trust our own.
				response.Header.ResCode = recursiveResp.Header.ResCode
			} else {
				s.Logger.Error("recursive error", "error", err, "name", q.Name)
				response.Header.ResCode = 2 // SERVFAIL
			}
		} else {
			response.Header.ResCode = 3 // NXDOMAIN
		}
	} else {
		response.Header.ResCode = 4 // FORMERR
	}

	// 5. Serialize and Handle Truncation
	resBuffer := packet.NewBytePacketBuffer()
	if err := response.Write(resBuffer); err != nil {
		s.Logger.Error("serialization error", "error", err)
		return err
	}

	// Check if we need to truncate (for UDP)
	// Note: In a production DNS, you would remove records one by one until it fits.
	// For this scratch implementation, we set TC bit if it exceeds limit.
	if resBuffer.Position() > int(maxUDPSize) {
		response.Header.TruncatedMessage = true
		// Clear answers to fit basic header
		response.Answers = nil
		response.Authorities = nil
		resBuffer = packet.NewBytePacketBuffer()
		response.Write(resBuffer)
	}

	resData := resBuffer.Buf[:resBuffer.Position()]

	// 6. Cache successful response
	if len(request.Questions) > 0 && (response.Header.ResCode == 0 || response.Header.ResCode == 3) {
		q := request.Questions[0]
		cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)
		cacheData := make([]byte, len(resData))
		copy(cacheData, resData)
		s.Cache.Set(cacheKey, cacheData, time.Duration(minTTL)*time.Second)
	}

	// 7. Send Back
	err := sendFn(resData)
	s.Logger.Info("dns query",
		"name", queryName,
		"type", queryType,
		"rcode", response.Header.ResCode,
		"cache", "miss",
		"latency", time.Since(start),
	)
	return err
}
