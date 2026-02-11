package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"syscall"
	"time"

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

	// Testing/Chaos flags
	SimulateDBLatency time.Duration

	// TLS Config for DoT and DoH
	TLSConfig *tls.Config
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

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
			})
		},
	}

	// 1. Parallel UDP
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
				if err != nil { continue }
				data := make([]byte, n)
				copy(data, buf[:n])
				s.udpQueue <- udpTask{addr: addr, data: data, conn: conn}
			}
		}(i)
	}

	// 2. UDP Workers
	for i := 0; i < s.WorkerCount; i++ {
		go s.udpWorker()
	}

	// 3. TCP Listener
	tcpListener, err := lc.Listen(context.Background(), "tcp", s.Addr)
	if err == nil {
		go func() {
			defer tcpListener.Close()
			for {
				conn, err := tcpListener.Accept()
				if err != nil { continue }
				go s.handleTCPConnection(conn)
			}
		}()
	}

	// 4. DoT Listener (Port 853)
	if s.TLSConfig != nil {
		host, _, _ := net.SplitHostPort(s.Addr)
		dotAddr := net.JoinHostPort(host, "853")
		dotListener, err := tls.Listen("tcp", dotAddr, s.TLSConfig)
		if err == nil {
			s.Logger.Info("DNS over TLS (DoT) starting", "addr", dotAddr)
			go func() {
				defer dotListener.Close()
				for {
					conn, err := dotListener.Accept()
					if err != nil { continue }
					go s.handleTCPConnection(conn)
				}
			}()
		}

		// 5. DoH Listener (Port 443)
		dohAddr := net.JoinHostPort(host, "443")
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", s.handleDoH)
		dohServer := &http.Server{Addr: dohAddr, Handler: mux, TLSConfig: s.TLSConfig}
		s.Logger.Info("DNS over HTTPS (DoH) starting", "addr", dohAddr)
		go dohServer.ListenAndServeTLS("", "")
	}

	select {}
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	s.handlePacket(body, r.RemoteAddr, func(resp []byte) error {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
		return nil
	})
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
	for {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil { return }
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
		data := make([]byte, packetLen)
		if _, err := io.ReadFull(conn, data); err != nil { return }
		s.handlePacket(data, conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp))
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, err := conn.Write(fullResp)
			return err
		})
	}
}

func (s *Server) handlePacket(data []byte, srcAddr interface{}, sendFn func([]byte) error) error {
	start := time.Now()
	
	var clientIP string
	switch addr := srcAddr.(type) {
	case string: clientIP, _, _ = net.SplitHostPort(addr)
	case net.Addr: clientIP, _, _ = net.SplitHostPort(addr.String())
	}

	if !s.limiter.Allow(clientIP) { return nil }

	reqBuffer := packet.GetBuffer()
	defer packet.PutBuffer(reqBuffer)
	reqBuffer.Load(data)

	request := packet.NewDnsPacket()
	if err := request.FromBuffer(reqBuffer); err != nil { return err }

	if len(request.Questions) == 0 { return nil }
	q := request.Questions[0]
	cacheKey := fmt.Sprintf("%s:%d", q.Name, q.QType)

	// L1/L2 Check
	if cachedData, found := s.Cache.Get(cacheKey); found {
		if len(cachedData) >= 2 {
			cachedData[0] = byte(request.Header.ID >> 8)
			cachedData[1] = byte(request.Header.ID & 0xFF)
		}
		return sendFn(cachedData)
	}
	if s.Redis != nil {
		if cachedData, found := s.Redis.Get(context.Background(), cacheKey); found {
			s.Cache.Set(cacheKey, cachedData, 60*time.Second)
			return sendFn(cachedData)
		}
	}

	// L3 Resolution
	if s.SimulateDBLatency > 0 {
		time.Sleep(time.Duration(float64(s.SimulateDBLatency) * (0.5 + rand.Float64())))
	}

	response := packet.NewDnsPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, q)

	var minTTL uint32 = 300
	source := "local"

	if q.QType == packet.A {
		ips, err := s.Repo.GetIPsForName(context.Background(), q.Name, clientIP)
		if err == nil && len(ips) > 0 {
			source = "local-fast"
			for _, ipStr := range ips {
				response.Answers = append(response.Answers, packet.DnsRecord{Name: q.Name, Type: packet.A, Class: 1, TTL: minTTL, IP: net.ParseIP(ipStr)})
			}
		} else {
			response.Header.ResCode = 3 // NXDOMAIN
			minTTL = 60
		}
	}

	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	response.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]

	if response.Header.ResCode == 0 || response.Header.ResCode == 3 {
		cacheData := make([]byte, len(resData))
		copy(cacheData, resData)
		s.Cache.Set(cacheKey, cacheData, time.Duration(minTTL)*time.Second)
		if s.Redis != nil { s.Redis.Set(context.Background(), cacheKey, cacheData, time.Duration(minTTL)*time.Second) }
	}

	s.Logger.Info("query processed", "name", q.Name, "src", source, "lat", time.Since(start).Milliseconds())
	return sendFn(resData)
}
