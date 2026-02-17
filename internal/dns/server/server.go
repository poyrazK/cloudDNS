package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type Server struct {
	Addr        string
	Repo        ports.DNSRepository
	Cache       *DNSCache
	Redis       *RedisCache
	DNSSEC      *services.DNSSECService
	WorkerCount int
	udpQueue    chan udpTask
	Logger      *slog.Logger
	queryFn     func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error)
	limiter     *rateLimiter
	TsigKeys    map[string][]byte

	// Testing/Chaos flags
	SimulateDBLatency  time.Duration
	NotifyPortOverride int

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
		DNSSEC:      services.NewDNSSECService(repo),
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

	// Background DNSSEC automation: Run every hour
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			s.automateDNSSEC()
		}
	}()

	return s
}

func (s *Server) automateDNSSEC() {
	ctx := context.Background()
	// Get all zones
	zones, err := s.Repo.ListZones(ctx, "")
	if err != nil {
		return
	}

	for _, z := range zones {
		if err := s.DNSSEC.AutomateLifecycle(ctx, z.ID); err != nil {
			s.Logger.Error("DNSSEC automation failed for zone", "zone", z.Name, "error", err)
		}
	}
}

func (s *Server) Run() error {
	s.Logger.Info("starting parallel server", "addr", s.Addr, "listeners", runtime.NumCPU())

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setReusePort(fd)
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
				if err != nil {
					continue
				}
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
				if err != nil {
					continue
				}
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
					if err != nil {
						continue
					}
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
	var dnsMsg []byte
	var err error

	if r.Method == http.MethodGet {
		query := r.URL.Query().Get("dns")
		if query == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		dnsMsg, err = base64.RawURLEncoding.DecodeString(query)
		if err != nil {
			// Try with padding if raw fails
			dnsMsg, err = base64.URLEncoding.DecodeString(query)
			if err != nil {
				http.Error(w, "invalid base64", http.StatusBadRequest)
				return
			}
		}
	} else if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		dnsMsg, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.handlePacket(dnsMsg, r.RemoteAddr, func(resp []byte) error {
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
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
		data := make([]byte, packetLen)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}

		// Check for AXFR/IXFR
		reqBuffer := packet.GetBuffer()
		reqBuffer.Load(data)
		request := packet.NewDNSPacket()
		if err := request.FromBuffer(reqBuffer); err == nil && len(request.Questions) > 0 {
			if request.Questions[0].QType == packet.AXFR {
				s.handleAXFR(conn, request)
				packet.PutBuffer(reqBuffer)
				continue
			}
			if request.Questions[0].QType == packet.IXFR {
				s.handleIXFR(conn, request)
				packet.PutBuffer(reqBuffer)
				continue
			}
		}
		packet.PutBuffer(reqBuffer)

		if err := s.handlePacket(data, conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp))
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, err := conn.Write(fullResp)
			return err
		}); err != nil {
			s.Logger.Error("Failed to handle TCP packet", "error", err)
		}
	}
}

func (s *Server) handleAXFR(conn net.Conn, request *packet.DNSPacket) {
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	ctx := context.Background()
	zone, _ := s.Repo.GetZone(ctx, q.Name)
	if zone == nil {
		s.Logger.Warn("AXFR requested for non-existent zone", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 3) // NXDOMAIN
		return
	}

	records, err := s.Repo.ListRecordsForZone(ctx, zone.ID)
	if err != nil {
		s.Logger.Error("AXFR failed to list records", "zone", zone.ID, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
		return
	}

	var soa *domain.Record
	for _, rec := range records {
		if rec.Type == domain.TypeSOA {
			soa = &rec
			break
		}
	}

	if soa == nil {
		s.Logger.Error("AXFR failed: zone has no SOA", "zone", zone.Name)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	// Filter out the SOA record from the main list to avoid duplication if it's already there
	var otherRecords []domain.Record
	for _, rec := range records {
		if rec.Type != domain.TypeSOA {
			otherRecords = append(otherRecords, rec)
		}
	}

	// Stream packets: SOA -> [all other records] -> SOA
	stream := append([]domain.Record{*soa}, otherRecords...)
	stream = append(stream, *soa)

	s.Logger.Info("AXFR starting", "zone", zone.Name, "records", len(stream))

	for i, rec := range stream {
		pRec, err := repository.ConvertDomainToPacketRecord(rec)
		if err != nil {
			s.Logger.Error("AXFR failed to convert record", "type", rec.Type, "error", err)
			continue
		}

		response := packet.NewDNSPacket()
		response.Header.ID = request.Header.ID
		response.Header.Response = true
		response.Header.AuthoritativeAnswer = true
		response.Questions = append(response.Questions, q)
		response.Answers = append(response.Answers, pRec)

		resBuffer := packet.GetBuffer()
		resBuffer.HasNames = true
		if err := response.Write(resBuffer); err != nil {
			s.Logger.Error("AXFR failed to write response", "error", err)
			packet.PutBuffer(resBuffer)
			continue
		}
		resData := resBuffer.Buf[:resBuffer.Position()]

		resLen := uint16(len(resData))
		fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
		if _, err := conn.Write(fullResp); err != nil {
			s.Logger.Error("AXFR connection broken", "error", err)
			packet.PutBuffer(resBuffer)
			return
		}
		s.Logger.Debug("AXFR sent packet", "index", i, "type", pRec.Type)
		packet.PutBuffer(resBuffer)
	}
	s.Logger.Info("AXFR completed", "zone", zone.Name)
}

func (s *Server) sendTCPError(conn net.Conn, id uint16, rcode uint8) {
	response := packet.NewDNSPacket()
	response.Header.ID = id
	response.Header.Response = true
	response.Header.ResCode = rcode
	resBuffer := packet.GetBuffer()
	response.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData))
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	conn.Write(fullResp)
	packet.PutBuffer(resBuffer)
}

func (s *Server) handlePacket(data []byte, srcAddr interface{}, sendFn func([]byte) error) error {
	start := time.Now()

	var clientIP string
	switch addr := srcAddr.(type) {
	case string:
		clientIP, _, _ = net.SplitHostPort(addr)
	case net.Addr:
		clientIP, _, _ = net.SplitHostPort(addr.String())
	}

	if !s.limiter.Allow(clientIP) {
		return nil
	}

	reqBuffer := packet.GetBuffer()
	defer packet.PutBuffer(reqBuffer)
	reqBuffer.Load(data)

	request := packet.NewDNSPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		s.Logger.Error("failed to parse packet", "error", err)
		return err
	}

	if request.Header.Opcode == packet.OPCODE_UPDATE {
		return s.handleUpdate(request, data, clientIP, sendFn)
	}

	if request.Header.Opcode == packet.OPCODE_NOTIFY {
		return s.handleNotify(request, clientIP, sendFn)
	}

	if len(request.Questions) == 0 {
		response := packet.NewDNSPacket()
		response.Header.ID = request.Header.ID
		response.Header.Response = true
		response.Header.ResCode = 4 // FORMERR
		resBuffer := packet.GetBuffer()
		defer packet.PutBuffer(resBuffer)
		response.Write(resBuffer)
		return sendFn(resBuffer.Buf[:resBuffer.Position()])
	}

	q := request.Questions[0]
	// Standardize name for lookup
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}
	cacheKey := fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.QType)

	// L1/L2 Check
	if cachedData, found := s.Cache.Get(cacheKey); found {
		// Rewrite Transaction ID
		if len(cachedData) >= 2 {
			cachedData[0] = byte(request.Header.ID >> 8)
			cachedData[1] = byte(request.Header.ID & 0xFF)
		}
		return sendFn(cachedData)
	}
	if s.Redis != nil {
		if cachedData, found := s.Redis.Get(context.Background(), cacheKey); found {
			// Rewrite Transaction ID
			if len(cachedData) >= 2 {
				cachedData[0] = byte(request.Header.ID >> 8)
				cachedData[1] = byte(request.Header.ID & 0xFF)
			}
			s.Cache.Set(cacheKey, cachedData, 60*time.Second)
			return sendFn(cachedData)
		}
	}

	// L3 Resolution
	if s.SimulateDBLatency > 0 {
		time.Sleep(time.Duration(float64(s.SimulateDBLatency) * (0.5 + rand.Float64())))
	}

	// EDNS(0) Support (RFC 6891)
	maxSize := 512
	dnssecOK := false
	var clientOPT *packet.DNSRecord
	for _, res := range request.Resources {
		if res.Type == packet.OPT {
			clientOPT = &res
			maxSize = int(res.UDPPayloadSize)
			if maxSize < 512 {
				maxSize = 512
			}
			// DO bit is the first bit of the Z field (TTL bits 15-0)
			dnssecOK = (res.Z & 0x8000) != 0
			break
		}
	}

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, q)

	// If query had EDNS, response MUST have EDNS
	if clientOPT != nil {
		opt := packet.DNSRecord{
			Name:           ".",
			Type:           packet.OPT,
			UDPPayloadSize: 4096, // Our server's supported buffer size
			TTL:            0,    // Extended RCODE and Version
		}
		if dnssecOK {
			opt.Z = 0x8000 // Set DO bit if client set it
		}
		response.Resources = append(response.Resources, opt)
	}

	ctx := context.Background()
	source := "local"

	// 1. Find the zone for this query to include Authority/Additional records
	zoneName := q.Name
	var zone *domain.Zone
	for {
		z, _ := s.Repo.GetZone(ctx, zoneName)
		if z != nil {
			zone = z
			break
		}
		idx := strings.Index(zoneName, ".")
		if idx == -1 || idx == len(zoneName)-1 {
			break
		}
		zoneName = zoneName[idx+1:]
	}

	// 2. Resolve Main Records
	qTypeStr := queryTypeToRecordType(q.QType)
	records, err := s.Repo.GetRecords(ctx, q.Name, qTypeStr, clientIP)
	if err == nil && len(records) > 0 {
		for _, rec := range records {
			pRec, err := repository.ConvertDomainToPacketRecord(rec)
			if err == nil {
				response.Answers = append(response.Answers, pRec)
			}
		}
	} else if zone != nil {
		// Try wildcard matching if no direct records found
		labels := strings.Split(strings.TrimSuffix(q.Name, "."), ".")
		for i := 0; i < len(labels)-1; i++ {
			wildcardName := "*." + strings.Join(labels[i+1:], ".") + "."
			wildcardRecords, err := s.Repo.GetRecords(ctx, wildcardName, qTypeStr, clientIP)
			if err == nil && len(wildcardRecords) > 0 {
				source = "wildcard"
				for _, rec := range wildcardRecords {
					rec.Name = q.Name // RFC: Rewrite wildcard to query name
					pRec, err := repository.ConvertDomainToPacketRecord(rec)
					if err == nil {
						response.Answers = append(response.Answers, pRec)
					}
				}
				break
			}
		}
	}

	// 3. Handle NXDOMAIN / No Data
	if len(response.Answers) == 0 {
		if zone != nil {
			response.Header.ResCode = 3 // NXDOMAIN
			// RFC: Include SOA in Authority section for negative caching
			soaRecords, _ := s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, clientIP)
			for _, rec := range soaRecords {
				pRec, err := repository.ConvertDomainToPacketRecord(rec)
				if err == nil {
					response.Authorities = append(response.Authorities, pRec)
				}
			}

			// DNSSEC: If DO bit is set, include NSEC or NSEC3 record
			if dnssecOK {
				// Check for NSEC3PARAM to decide between NSEC and NSEC3
				nsec3params, _ := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
				if len(nsec3params) > 0 {
					nsec3, err := s.generateNSEC3(ctx, zone, q.Name)
					if err == nil {
						response.Authorities = append(response.Authorities, nsec3)
					}
				} else {
					nsec, err := s.generateNSEC(ctx, zone, q.Name)
					if err == nil {
						response.Authorities = append(response.Authorities, nsec)
					}
				}
			}
		} else {
			// Not authoritative for this zone
			response.Header.AuthoritativeAnswer = false
			response.Header.ResCode = 3
		}

		// RFC 8914: Extended DNS Error (EDE)
		if clientOPT != nil {
			for i := range response.Resources {
				if response.Resources[i].Type == packet.OPT {
					response.Resources[i].AddEDE(packet.EDE_OTHER, "")
				}
			}
		}
	} else if zone != nil {
		// 4. Populate Authority Section (NS records)
		nsRecords, _ := s.Repo.GetRecords(ctx, zone.Name, domain.TypeNS, clientIP)
		for _, rec := range nsRecords {
			pRec, err := repository.ConvertDomainToPacketRecord(rec)
			if err == nil {
				response.Authorities = append(response.Authorities, pRec)

				// 5. Populate Additional Section (Glue records)
				glueRecords, _ := s.Repo.GetRecords(ctx, pRec.Host, domain.TypeA, clientIP)
				for _, gRec := range glueRecords {
					gpRec, err := repository.ConvertDomainToPacketRecord(gRec)
					if err == nil {
						response.Resources = append(response.Resources, gpRec)
					}
				}
			}
		}
	}

	// Dynamic RRSIG generation if DO bit is set
	if dnssecOK && zone != nil {
		s.signResponse(ctx, zone, response)
	}

	// Handle Truncation
	for _, res := range request.Resources {
		if res.Type == packet.OPT {
			maxSize = int(res.UDPPayloadSize)
			if maxSize < 512 {
				maxSize = 512
			}
			break
		}
	}

	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	resBuffer.HasNames = true // Enable Name Compression
	response.Write(resBuffer)

	if resBuffer.Position() > maxSize {
		response.Header.TruncatedMessage = true
		response.Answers = nil
		response.Authorities = nil
		response.Resources = nil
		resBuffer.Reset()
		resBuffer.HasNames = true
		response.Write(resBuffer)
	}

	resData := resBuffer.Buf[:resBuffer.Position()]

	// Cache the result
	var ttl uint32 = 300
	if len(response.Answers) > 0 {
		ttl = response.Answers[0].TTL
	} else if len(response.Authorities) > 0 {
		ttl = response.Authorities[0].TTL
	}

	if (response.Header.ResCode == 0 || response.Header.ResCode == 3) && !response.Header.TruncatedMessage {
		cacheData := make([]byte, len(resData))
		copy(cacheData, resData)
		s.Cache.Set(cacheKey, cacheData, time.Duration(ttl)*time.Second)
		if s.Redis != nil {
			s.Redis.Set(ctx, cacheKey, cacheData, time.Duration(ttl)*time.Second)
		}
	}

	s.Logger.Info("query processed", "name", q.Name, "src", source, "lat", time.Since(start).Milliseconds())
	return sendFn(resData)
}

func (s *Server) handleNotify(request *packet.DNSPacket, clientIP string, sendFn func([]byte) error) error {
	zoneName := request.Questions[0].Name
	s.Logger.Info("received NOTIFY", "zone", zoneName, "from", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OPCODE_NOTIFY
	response.Header.AuthoritativeAnswer = true
	if len(request.Questions) > 0 {
		response.Questions = append(response.Questions, request.Questions[0])
	}

	// Acknowledge immediately per RFC 1996, then trigger async refresh
	response.Header.ResCode = packet.RCODE_NOERROR
	if err := s.sendUpdateResponse(response, sendFn); err != nil {
		return err
	}

	// Trigger zone refresh asynchronously
	go s.refreshZoneFromMaster(zoneName, clientIP)

	return nil
}

// refreshZoneFromMaster queries the master for SOA, compares serials, and performs IXFR/AXFR if needed.
// This is triggered when we receive a NOTIFY and act as a slave for the zone.
func (s *Server) refreshZoneFromMaster(zoneName, masterAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.Logger.Info("starting zone refresh", "zone", zoneName, "master", masterAddr)

	// 1. Query master's SOA to get current serial
	masterSOA, err := s.querySOA(ctx, masterAddr, zoneName)
	if err != nil {
		s.Logger.Error("failed to query master SOA", "zone", zoneName, "error", err)
		return
	}

	// 2. Get our local SOA serial
	localSerial, err := s.getLocalSOASerial(ctx, zoneName)
	if err != nil {
		s.Logger.Error("failed to get local SOA", "zone", zoneName, "error", err)
		return
	}

	// 3. Compare serials (RFC 1982 serial arithmetic)
	if !serialGreater(masterSOA.Serial, localSerial) {
		s.Logger.Info("zone is up to date", "zone", zoneName, "local", localSerial, "master", masterSOA.Serial)
		return
	}

	s.Logger.Info("zone needs update", "zone", zoneName, "local", localSerial, "master", masterSOA.Serial)

	// 4. Attempt IXFR first, fall back to AXFR
	if err := s.performIXFR(ctx, masterAddr, zoneName, localSerial); err != nil {
		s.Logger.Warn("IXFR failed, falling back to AXFR", "zone", zoneName, "error", err)
		if err := s.performAXFR(ctx, masterAddr, zoneName); err != nil {
			s.Logger.Error("AXFR failed", "zone", zoneName, "error", err)
			return
		}
	}

	s.Logger.Info("zone refresh complete", "zone", zoneName)
}

// querySOA sends a SOA query to the specified server and returns the SOA record.
func (s *Server) querySOA(ctx context.Context, serverAddr, zoneName string) (*packet.DNSRecord, error) {
	// Ensure port is specified
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "53")
	}

	req := packet.NewDNSPacket()
	req.Header.ID = uint16(rand.Intn(65535))
	req.Header.RecursionDesired = false
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:  zoneName,
		QType: packet.SOA,
	})

	// Use UDP for SOA query
	conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	buf := packet.NewBytePacketBuffer()
	if err := req.Write(buf); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(buf.Buf[:buf.Position()]); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	resp := packet.NewDNSPacket()
	respPacket := packet.NewBytePacketBuffer()
	copy(respPacket.Buf[:], respBuf[:n])
	if err := resp.FromBuffer(respPacket); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	for _, ans := range resp.Answers {
		if ans.Type == packet.SOA {
			return &ans, nil
		}
	}

	return nil, fmt.Errorf("no SOA record in response")
}

// getLocalSOASerial retrieves the serial number from our local SOA record.
func (s *Server) getLocalSOASerial(ctx context.Context, zoneName string) (uint32, error) {
	zone, err := s.Repo.GetZone(ctx, zoneName)
	if err != nil || zone == nil {
		return 0, fmt.Errorf("zone not found: %s", zoneName)
	}

	records, err := s.Repo.ListRecordsForZone(ctx, zone.ID)
	if err != nil {
		return 0, fmt.Errorf("failed to list records: %w", err)
	}

	for _, rec := range records {
		if rec.Type == domain.TypeSOA {
			// Parse SOA content: "ns1.example.com. admin.example.com. 2024010100 3600 600 604800 300"
			var mname, rname string
			var serial, refresh, retry, expire, minimum uint32
			_, err := fmt.Sscanf(rec.Content, "%s %s %d %d %d %d %d",
				&mname, &rname, &serial, &refresh, &retry, &expire, &minimum)
			if err != nil {
				return 0, fmt.Errorf("failed to parse SOA: %w", err)
			}
			return serial, nil
		}
	}

	return 0, fmt.Errorf("no SOA record found")
}

// serialGreater implements RFC 1982 serial number arithmetic.
// Returns true if s1 > s2 (s1 is "greater" than s2).
func serialGreater(s1, s2 uint32) bool {
	if s1 == s2 {
		return false
	}
	// RFC 1982: s1 > s2 if (s1 < s2 && s2 - s1 > 2^31) || (s1 > s2 && s1 - s2 < 2^31)
	return (s1 < s2 && s2-s1 > 0x80000000) || (s1 > s2 && s1-s2 < 0x80000000)
}

// performIXFR attempts an incremental zone transfer from the master.
func (s *Server) performIXFR(ctx context.Context, masterAddr, zoneName string, localSerial uint32) error {
	// Ensure port is specified
	if _, _, err := net.SplitHostPort(masterAddr); err != nil {
		masterAddr = net.JoinHostPort(masterAddr, "53")
	}

	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Build IXFR request with our current SOA in authority section
	req := packet.NewDNSPacket()
	req.Header.ID = uint16(rand.Intn(65535))
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:  zoneName,
		QType: packet.IXFR,
	})

	// Add our current SOA to authority section to indicate our serial
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:   zoneName,
		Type:   packet.SOA,
		Class:  1, // IN (Internet)
		TTL:    0,
		Serial: localSerial,
	})
	req.Header.AuthoritativeEntries = 1

	// Send with TCP length prefix
	buf := packet.NewBytePacketBuffer()
	if err := req.Write(buf); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	data := buf.Buf[:buf.Position()]
	lenBuf := make([]byte, 2)
	lenBuf[0] = byte(len(data) >> 8)
	lenBuf[1] = byte(len(data))

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	// Read response - for now just log success, actual record application would need repo changes
	respLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, respLenBuf); err != nil {
		return fmt.Errorf("failed to read response length: %w", err)
	}

	respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	resp := packet.NewDNSPacket()
	respBuf := packet.NewBytePacketBuffer()
	copy(respBuf.Buf[:], respData)
	if err := resp.FromBuffer(respBuf); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if resp.Header.ResCode != packet.RCODE_NOERROR {
		return fmt.Errorf("IXFR failed with rcode %d", resp.Header.ResCode)
	}

	// Check if server responded with full AXFR (single SOA means "do AXFR instead")
	soaCount := 0
	for _, ans := range resp.Answers {
		if ans.Type == packet.SOA {
			soaCount++
		}
	}
	if soaCount < 2 {
		return fmt.Errorf("server indicated AXFR required")
	}

	s.Logger.Info("IXFR response received", "zone", zoneName, "answers", len(resp.Answers))
	// Note: Actually applying the IXFR changes would require repository modifications
	return nil
}

// performAXFR performs a full zone transfer from the master.
func (s *Server) performAXFR(ctx context.Context, masterAddr, zoneName string) error {
	// Ensure port is specified
	if _, _, err := net.SplitHostPort(masterAddr); err != nil {
		masterAddr = net.JoinHostPort(masterAddr, "53")
	}

	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	req := packet.NewDNSPacket()
	req.Header.ID = uint16(rand.Intn(65535))
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:  zoneName,
		QType: packet.AXFR,
	})

	buf := packet.NewBytePacketBuffer()
	if err := req.Write(buf); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	data := buf.Buf[:buf.Position()]
	lenBuf := make([]byte, 2)
	lenBuf[0] = byte(len(data) >> 8)
	lenBuf[1] = byte(len(data))

	conn.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	// Read all AXFR responses until we see the closing SOA
	var allRecords []packet.DNSRecord
	seenFirstSOA := false

	for {
		respLenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, respLenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read response length: %w", err)
		}

		respLen := int(respLenBuf[0])<<8 | int(respLenBuf[1])
		respData := make([]byte, respLen)
		if _, err := io.ReadFull(conn, respData); err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		resp := packet.NewDNSPacket()
		respBuf := packet.NewBytePacketBuffer()
		copy(respBuf.Buf[:], respData)
		if err := resp.FromBuffer(respBuf); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		if resp.Header.ResCode != packet.RCODE_NOERROR {
			return fmt.Errorf("AXFR failed with rcode %d", resp.Header.ResCode)
		}

		for _, ans := range resp.Answers {
			allRecords = append(allRecords, ans)
			if ans.Type == packet.SOA {
				if seenFirstSOA {
					// Second SOA marks end of transfer
					s.Logger.Info("AXFR complete", "zone", zoneName, "records", len(allRecords))
					// Note: Actually applying records would require repository modifications
					return nil
				}
				seenFirstSOA = true
			}
		}
	}

	return fmt.Errorf("AXFR incomplete: did not receive closing SOA")
}

func (s *Server) handleUpdate(request *packet.DNSPacket, rawData []byte, clientIP string, sendFn func([]byte) error) error {
	s.Logger.Info("handling dynamic update", "id", request.Header.ID, "client", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OPCODE_UPDATE

	// 1. Validate TSIG if present
	if request.TSIGStart != -1 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Warn("update failed: unknown TSIG key", "key", tsig.Name)
			response.Header.ResCode = packet.RCODE_NOTAUTH
			return s.sendUpdateResponse(response, sendFn)
		}
		if err := request.VerifyTSIG(rawData, request.TSIGStart, secret); err != nil {
			s.Logger.Warn("update failed: TSIG verification failed", "error", err)
			response.Header.ResCode = packet.RCODE_NOTAUTH
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 2. Validate Zone Section (ZOCOUNT must be 1)
	if len(request.Questions) != 1 {
		s.Logger.Warn("update failed: ZOCOUNT != 1", "count", len(request.Questions))
		response.Header.ResCode = packet.RCODE_FORMERR
		return s.sendUpdateResponse(response, sendFn)
	}

	zone := request.Questions[0]
	if !strings.HasSuffix(zone.Name, ".") {
		zone.Name += "."
	}
	response.Questions = append(response.Questions, zone)

	ctx := context.Background()
	dbZone, _ := s.Repo.GetZone(ctx, zone.Name)
	if dbZone == nil {
		s.Logger.Warn("update failed: not authoritative for zone", "zone", zone.Name)
		response.Header.ResCode = packet.RCODE_NOTAUTH
		return s.sendUpdateResponse(response, sendFn)
	}

	// 2. Prerequisite Checks (PRCOUNT)
	for _, pr := range request.Answers {
		if err := s.checkPrerequisite(ctx, dbZone, pr); err != nil {
			s.Logger.Warn("update failed: prerequisite mismatch", "pr", pr.Name, "error", err)
			if uErr, ok := err.(updateError); ok {
				response.Header.ResCode = uint8(uErr.rcode)
			} else {
				response.Header.ResCode = packet.RCODE_SERVFAIL
			}
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 3. Perform Updates (UPCOUNT)
	var newSerial uint32
	var changes []domain.ZoneChange

	for _, up := range request.Authorities {
		if err := s.applyUpdate(ctx, dbZone, up); err != nil {
			s.Logger.Error("update failed: failed to apply record change", "up", up.Name, "error", err)
			response.Header.ResCode = packet.RCODE_SERVFAIL
			return s.sendUpdateResponse(response, sendFn)
		}

		// Record change for IXFR
		change := domain.ZoneChange{
			ID:        fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int()),
			ZoneID:    dbZone.ID,
			Name:      up.Name,
			Type:      domain.RecordType(up.Type.String()),
			TTL:       int(up.TTL),
			CreatedAt: time.Now(),
		}
		if up.Class == 255 || up.Class == 254 {
			change.Action = "DELETE"
		} else {
			change.Action = "ADD"
			dRec, _ := repository.ConvertPacketRecordToDomain(up, dbZone.ID)
			change.Content = dRec.Content
			if dRec.Priority != nil {
				change.Priority = dRec.Priority
			}
		}
		changes = append(changes, change)
	}

	// 4. Increment Serial if changes occurred
	if len(changes) > 0 {
		soaRecords, _ := s.Repo.GetRecords(ctx, dbZone.Name, domain.TypeSOA, "")
		if len(soaRecords) > 0 {
			soa := soaRecords[0]
			parts := strings.Fields(soa.Content)
			if len(parts) >= 3 {
				fmt.Sscanf(parts[2], "%d", &newSerial)
				newSerial++
				parts[2] = fmt.Sprintf("%d", newSerial)
				soa.Content = strings.Join(parts, " ")

				// Delete old SOA and create new one (simplified update)
				s.Repo.DeleteRecord(ctx, soa.ID, dbZone.ID)
				s.Repo.CreateRecord(ctx, &soa)

				// Persist changes with the new serial
				for _, c := range changes {
					c.Serial = newSerial
					s.Repo.RecordZoneChange(ctx, &c)
				}
			}
		}
	}

	// 5. Success
	response.Header.ResCode = packet.RCODE_NOERROR
	s.Logger.Info("dynamic update successful", "zone", zone.Name)
	s.Cache.Flush()

	// 6. Trigger NOTIFY (RFC 1996)
	go s.notifySlaves(zone.Name)

	return s.sendUpdateResponse(response, sendFn)
}

func (s *Server) handleIXFR(conn net.Conn, request *packet.DNSPacket) {
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// RFC 1995: The client's current SOA is in the Authority section
	if len(request.Authorities) == 0 || request.Authorities[0].Type != packet.SOA {
		s.Logger.Warn("IXFR requested without client SOA in Authority section", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 1) // FORMERR
		return
	}
	clientSOA := request.Authorities[0]
	clientSerial := clientSOA.Serial

	ctx := context.Background()
	zone, _ := s.Repo.GetZone(ctx, q.Name)
	if zone == nil {
		s.Logger.Warn("IXFR requested for non-existent zone", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 3) // NXDOMAIN
		return
	}

	// Get current SOA
	soaRecords, _ := s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, "")
	if len(soaRecords) == 0 {
		s.Logger.Error("IXFR failed: zone has no SOA", "zone", zone.Name)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}
	currentSOA := soaRecords[0]
	var currentSerial uint32
	fmt.Sscanf(strings.Fields(currentSOA.Content)[2], "%d", &currentSerial)

	if clientSerial == currentSerial {
		// Client is up to date, just send current SOA
		s.Logger.Info("IXFR client is up to date", "zone", zone.Name, "serial", clientSerial)
		pSOA, _ := repository.ConvertDomainToPacketRecord(currentSOA)
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)
		return
	}

	// Fetch changes since clientSerial
	changes, err := s.Repo.ListZoneChanges(ctx, zone.ID, clientSerial)
	if err != nil || len(changes) == 0 {
		s.Logger.Info("IXFR history not found, falling back to AXFR", "zone", zone.Name, "client_serial", clientSerial)
		s.handleAXFR(conn, request)
		return
	}

	s.Logger.Info("IXFR starting", "zone", zone.Name, "from", clientSerial, "to", currentSerial)

	// Send Current SOA (marks start of IXFR)
	pCurrentSOA, _ := repository.ConvertDomainToPacketRecord(currentSOA)
	s.sendSingleRecordResponse(conn, request.Header.ID, q, pCurrentSOA)

	// Send diffs: [Old SOA, Deleted RRs, New SOA, Added RRs]
	currentDiffSerial := clientSerial
	var deletions, additions []packet.DNSRecord

	for _, c := range changes {
		if c.Serial > currentDiffSerial {
			// We moved to a new version. If we have accumulated diffs, send them.
			if len(deletions) > 0 || len(additions) > 0 {
				tempSOA := pCurrentSOA
				tempSOA.Serial = currentDiffSerial

				s.sendIXFRDiff(conn, request.Header.ID, q, tempSOA, deletions, additions)
				deletions = nil
				additions = nil
			}
			currentDiffSerial = c.Serial
		}

		pRec := packet.DNSRecord{
			Name:  c.Name,
			Type:  packet.QueryType(master.RecordTypeToQueryType(c.Type)),
			TTL:   uint32(c.TTL),
			Class: 1,
		}

		if c.Action == "DELETE" {
			deletions = append(deletions, pRec)
		} else {
			additions = append(additions, pRec)
		}
	}

	// Send last diff if any
	if len(deletions) > 0 || len(additions) > 0 {
		tempSOA := pCurrentSOA
		tempSOA.Serial = currentDiffSerial
		s.sendIXFRDiff(conn, request.Header.ID, q, tempSOA, deletions, additions)
	}

	// Send Current SOA (marks end of IXFR)
	s.sendSingleRecordResponse(conn, request.Header.ID, q, pCurrentSOA)
	s.Logger.Info("IXFR completed", "zone", zone.Name)
}

func (s *Server) signResponse(ctx context.Context, zone *domain.Zone, response *packet.DNSPacket) {
	// Sign Answers
	if len(response.Answers) > 0 {
		groups := s.groupRecords(response.Answers)
		for _, group := range groups {
			sigs, err := s.DNSSEC.SignRRSet(ctx, zone.Name, zone.ID, group)
			if err == nil {
				for _, sig := range sigs {
					response.Answers = append(response.Answers, sig)
				}
			}
		}
	}
	// Sign Authorities
	if len(response.Authorities) > 0 {
		groups := s.groupRecords(response.Authorities)
		for _, group := range groups {
			sigs, err := s.DNSSEC.SignRRSet(ctx, zone.Name, zone.ID, group)
			if err == nil {
				for _, sig := range sigs {
					response.Authorities = append(response.Authorities, sig)
				}
			}
		}
	}
}

func (s *Server) groupRecords(records []packet.DNSRecord) [][]packet.DNSRecord {
	groups := make(map[string][]packet.DNSRecord)
	var keys []string
	for _, r := range records {
		if r.Type == packet.RRSIG || r.Type == packet.OPT || r.Type == packet.TSIG {
			continue
		}
		key := fmt.Sprintf("%s:%d", strings.ToLower(r.Name), r.Type)
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], r)
	}

	var res [][]packet.DNSRecord
	for _, k := range keys {
		res = append(res, groups[k])
	}
	return res
}

func (s *Server) sendSingleRecordResponse(conn net.Conn, id uint16, q packet.DNSQuestion, rec packet.DNSRecord) {
	resp := packet.NewDNSPacket()
	resp.Header.ID = id
	resp.Header.Response = true
	resp.Header.AuthoritativeAnswer = true
	resp.Questions = append(resp.Questions, q)
	resp.Answers = append(resp.Answers, rec)

	resBuffer := packet.GetBuffer()
	resp.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData))
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	conn.Write(fullResp)
	packet.PutBuffer(resBuffer)
}

func (s *Server) sendIXFRDiff(conn net.Conn, id uint16, q packet.DNSQuestion, soa packet.DNSRecord, deletions, additions []packet.DNSRecord) {
	// 1. Send Old SOA + Deletions
	resp := packet.NewDNSPacket()
	resp.Header.ID = id
	resp.Header.Response = true
	resp.Answers = append(resp.Answers, soa)
	resp.Answers = append(resp.Answers, deletions...)

	resBuffer := packet.GetBuffer()
	resp.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData))
	conn.Write(append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...))
	packet.PutBuffer(resBuffer)

	// 2. Send New SOA + Additions
	resp = packet.NewDNSPacket()
	resp.Header.ID = id
	resp.Header.Response = true
	resp.Answers = append(resp.Answers, soa)
	resp.Answers[0].Serial++
	resp.Answers = append(resp.Answers, additions...)

	resBuffer = packet.GetBuffer()
	resp.Write(resBuffer)
	resData = resBuffer.Buf[:resBuffer.Position()]
	resLen = uint16(len(resData))
	conn.Write(append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...))
	packet.PutBuffer(resBuffer)
}

func (s *Server) sendUpdateResponse(resp *packet.DNSPacket, sendFn func([]byte) error) error {
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	resp.Write(resBuffer)
	return sendFn(resBuffer.Buf[:resBuffer.Position()])
}

type updateError struct {
	rcode int
	msg   string
}

func (e updateError) Error() string { return e.msg }

func (s *Server) checkPrerequisite(ctx context.Context, zone *domain.Zone, pr packet.DNSRecord) error {
	qTypeStr := queryTypeToRecordType(pr.Type)
	records, err := s.Repo.GetRecords(ctx, pr.Name, qTypeStr, "")
	if err != nil {
		return updateError{rcode: int(packet.RCODE_SERVFAIL), msg: "failed to fetch records for prerequisite check"}
	}

	switch {
	case pr.Class == 255: // ANY
		if pr.Type == 255 { // ANY
			if len(records) == 0 {
				return updateError{rcode: int(packet.RCODE_NXDOMAIN), msg: "name not in use"}
			}
		} else {
			if len(records) == 0 {
				return updateError{rcode: int(packet.RCODE_NXRRSET), msg: "rrset does not exist"}
			}
		}
	case pr.Class == 254: // NONE
		if pr.Type == 255 { // ANY
			if len(records) > 0 {
				return updateError{rcode: int(packet.RCODE_YXDOMAIN), msg: "name in use"}
			}
		} else {
			if len(records) > 0 {
				return updateError{rcode: int(packet.RCODE_YXRRSET), msg: "rrset exists"}
			}
		}
	default:
		if len(records) == 0 {
			return updateError{rcode: int(packet.RCODE_NXRRSET), msg: "rrset does not exist"}
		}
	}

	return nil
}

func (s *Server) applyUpdate(ctx context.Context, zone *domain.Zone, up packet.DNSRecord) error {
	switch {
	case up.Class == 255: // ANY
		if up.Type == 255 { // ANY
			return s.Repo.DeleteRecordsByName(ctx, zone.ID, up.Name)
		} else {
			qTypeStr := queryTypeToRecordType(up.Type)
			return s.Repo.DeleteRecordsByNameAndType(ctx, zone.ID, up.Name, qTypeStr)
		}
	case up.Class == 254: // NONE
		qTypeStr := queryTypeToRecordType(up.Type)
		dRec, err := repository.ConvertPacketRecordToDomain(up, zone.ID)
		if err != nil {
			return err
		}
		return s.Repo.DeleteRecordSpecific(ctx, zone.ID, up.Name, qTypeStr, dRec.Content)
	default:
		dRec, err := repository.ConvertPacketRecordToDomain(up, zone.ID)
		if err != nil {
			return err
		}
		if dRec.ID == "" {
			dRec.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int())
		}
		if dRec.CreatedAt.IsZero() {
			dRec.CreatedAt = time.Now()
			dRec.UpdatedAt = time.Now()
		}
		return s.Repo.CreateRecord(ctx, &dRec)
	}
}

func (s *Server) notifySlaves(zoneName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbZone, err := s.Repo.GetZone(ctx, zoneName)
	if err != nil || dbZone == nil {
		return
	}

	nsRecords, err := s.Repo.GetRecords(ctx, zoneName, domain.TypeNS, "")
	if err != nil {
		return
	}

	for _, ns := range nsRecords {
		ips, err := s.Repo.GetIPsForName(ctx, ns.Content, "")
		if err != nil || len(ips) == 0 {
			continue
		}

		for _, ip := range ips {
			// Skip logic: only skip if it's EXACTLY the same host:port
			targetPort := 53
			if s.NotifyPortOverride > 0 {
				targetPort = s.NotifyPortOverride
			}

			targetAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", targetPort))
			if s.Addr == targetAddr {
				continue
			}

			s.Logger.Info("sending NOTIFY", "zone", zoneName, "slave", targetAddr)

			notify := packet.NewDNSPacket()
			notify.Header.ID = uint16(rand.Intn(65535))
			notify.Header.Opcode = packet.OPCODE_NOTIFY
			notify.Header.AuthoritativeAnswer = true
			notify.Questions = append(notify.Questions, packet.DNSQuestion{
				Name:  zoneName,
				QType: packet.SOA,
			})

			buf := packet.GetBuffer()
			notify.Write(buf)
			data := buf.Buf[:buf.Position()]

			conn, err := net.Dial("udp", targetAddr)
			if err == nil {
				conn.Write(data)
				conn.Close()
			}
			packet.PutBuffer(buf)
		}
	}
}

func (s *Server) generateNSEC(ctx context.Context, zone *domain.Zone, queryName string) (packet.DNSRecord, error) {
	records, err := s.Repo.ListRecordsForZone(ctx, zone.ID)
	if err != nil {
		return packet.DNSRecord{}, err
	}

	master.SortRecordsCanonically(records)

	nameToTypes := make(map[string][]domain.RecordType)
	var uniqueNames []string
	seen := make(map[string]bool)
	for _, r := range records {
		if !seen[r.Name] {
			uniqueNames = append(uniqueNames, r.Name)
			seen[r.Name] = true
		}
		nameToTypes[r.Name] = append(nameToTypes[r.Name], r.Type)
	}

	if len(uniqueNames) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no records in zone")
	}

	var ownerName, nextName string
	found := false
	for i := 0; i < len(uniqueNames); i++ {
		cmp := master.CompareNamesCanonically(queryName, uniqueNames[i])
		if cmp < 0 {
			if i == 0 {
				ownerName = uniqueNames[len(uniqueNames)-1]
				nextName = uniqueNames[0]
			} else {
				ownerName = uniqueNames[i-1]
				nextName = uniqueNames[i]
			}
			found = true
			break
		}
		if cmp == 0 {
			ownerName = uniqueNames[i]
			if i == len(uniqueNames)-1 {
				nextName = uniqueNames[0]
			} else {
				nextName = uniqueNames[i+1]
			}
			found = true
			break
		}
	}

	if !found {
		ownerName = uniqueNames[len(uniqueNames)-1]
		nextName = uniqueNames[0]
	}

	types := nameToTypes[ownerName]
	types = append(types, "NSEC")
	bitmap := s.generateTypeBitMap(types)

	nsec := packet.DNSRecord{
		Name:       ownerName,
		Type:       packet.NSEC,
		Class:      1,
		TTL:        300,
		NextName:   nextName,
		TypeBitMap: bitmap,
	}

	return nsec, nil
}

func (s *Server) generateNSEC3(ctx context.Context, zone *domain.Zone, queryName string) (packet.DNSRecord, error) {
	params, err := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
	if err != nil || len(params) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no NSEC3PARAM")
	}

	parts := strings.Fields(params[0].Content)
	if len(parts) < 4 {
		return packet.DNSRecord{}, fmt.Errorf("invalid NSEC3PARAM")
	}

	var alg, flags uint8
	var iterations uint16
	fmt.Sscanf(parts[0], "%d", &alg)
	fmt.Sscanf(parts[1], "%d", &flags)
	fmt.Sscanf(parts[2], "%d", &iterations)
	salt := parts[3]
	if salt == "-" {
		salt = ""
	}

	records, _ := s.Repo.ListRecordsForZone(ctx, zone.ID)
	nameToTypes := make(map[string][]domain.RecordType)
	var ownerNames []string
	seen := make(map[string]bool)
	for _, r := range records {
		if !seen[r.Name] {
			ownerNames = append(ownerNames, r.Name)
			seen[r.Name] = true
		}
		nameToTypes[r.Name] = append(nameToTypes[r.Name], r.Type)
	}

	type hashEntry struct {
		name string
		hash []byte
	}
	var hashes []hashEntry
	for _, name := range ownerNames {
		h := packet.HashName(name, alg, iterations, []byte(salt))
		hashes = append(hashes, hashEntry{name: name, hash: h})
	}

	if len(hashes) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no records to hash for NSEC3")
	}

	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i].hash, hashes[j].hash) < 0
	})

	qHash := packet.HashName(queryName, alg, iterations, []byte(salt))
	var ownerEntry, nextEntry hashEntry
	found := false
	for i := 0; i < len(hashes); i++ {
		cmp := bytes.Compare(qHash, hashes[i].hash)
		if cmp < 0 {
			if i == 0 {
				ownerEntry = hashes[len(hashes)-1]
				nextEntry = hashes[0]
			} else {
				ownerEntry = hashes[i-1]
				nextEntry = hashes[i]
			}
			found = true
			break
		}
		if cmp == 0 {
			ownerEntry = hashes[i]
			if i == len(hashes)-1 {
				nextEntry = hashes[0]
			} else {
				nextEntry = hashes[i+1]
			}
			found = true
			break
		}
	}
	if !found {
		ownerEntry = hashes[len(hashes)-1]
		nextEntry = hashes[0]
	}

	types := nameToTypes[ownerEntry.name]
	types = append(types, "NSEC3")
	bitmap := s.generateTypeBitMap(types)

	nsec3 := packet.DNSRecord{
		Name:       packet.Base32Encode(ownerEntry.hash) + "." + zone.Name,
		Type:       packet.NSEC3,
		Class:      1,
		TTL:        300,
		HashAlg:    alg,
		Flags:      uint16(flags),
		Iterations: iterations,
		Salt:       []byte(salt),
		NextHash:   nextEntry.hash,
		TypeBitMap: bitmap,
	}

	return nsec3, nil
}

func (s *Server) generateTypeBitMap(types []domain.RecordType) []byte {
	bits := make([]byte, 32)
	maxType := 0
	for _, t := range types {
		qt := master.RecordTypeToQueryType(t)
		if qt == 0 {
			if t == "NSEC" {
				qt = 47
			}
			if t == "NSEC3" {
				qt = 50
			}
		}
		if qt == 0 || qt > 255 {
			continue
		}

		byteIdx := qt / 8
		bitIdx := 7 - (qt % 8)
		bits[byteIdx] |= (1 << bitIdx)
		if int(byteIdx) > maxType {
			maxType = int(byteIdx)
		}
	}

	res := []byte{0, byte(maxType + 1)}
	res = append(res, bits[:maxType+1]...)
	return res
}

func queryTypeToRecordType(qType packet.QueryType) domain.RecordType {
	switch qType {
	case packet.A:
		return domain.TypeA
	case packet.AAAA:
		return domain.TypeAAAA
	case packet.CNAME:
		return domain.TypeCNAME
	case packet.NS:
		return domain.TypeNS
	case packet.MX:
		return domain.TypeMX
	case packet.SRV:
		return domain.TypeSRV
	case packet.SOA:
		return domain.TypeSOA
	case packet.TXT:
		return domain.TypeTXT
	case packet.PTR:
		return domain.TypePTR
	case packet.ANY:
		return ""
	default:
		return ""
	}
}
