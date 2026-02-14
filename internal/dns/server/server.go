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

	// Background DNSSEC automation: Run every hour
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			s.automateDNSSEC()
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
	// Get all zones (simplified: we'd need a ListAllZones method or iterate over tenants)
	// For now, we use a placeholder or assume a way to discover active zones
	zones, err := s.Repo.ListZones(ctx, "") // Empty tenant might return all or we iterate
	if err != nil { return }

	for _, z := range zones {
		if err := s.DNSSEC.AutomateLifecycle(ctx, z.ID); err != nil {
			s.Logger.Error("DNSSEC automation failed for zone", "zone", z.Name, "error", err)
		}
	}
}

func (s *Server) automateDNSSEC() {
	ctx := context.Background()
	// Get all zones (simplified: we'd need a ListAllZones method or iterate over tenants)
	// For now, we use a placeholder or assume a way to discover active zones
	zones, err := s.Repo.ListZones(ctx, "") // Empty tenant might return all or we iterate
	if err != nil { return }

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
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
		data := make([]byte, packetLen)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}

		// Check for AXFR
		reqBuffer := packet.GetBuffer()
		reqBuffer.Load(data)
		request := packet.NewDnsPacket()
		if err := request.FromBuffer(reqBuffer); err == nil && len(request.Questions) > 0 {
			if request.Questions[0].QType == packet.AXFR {
				s.handleAXFR(conn, request)
				packet.PutBuffer(reqBuffer)
				continue
			}
		}
		packet.PutBuffer(reqBuffer)

		s.handlePacket(data, conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp))
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, err := conn.Write(fullResp)
			return err
		})
	}
}

func (s *Server) handleAXFR(conn net.Conn, request *packet.DnsPacket) {
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

		response := packet.NewDnsPacket()
		response.Header.ID = request.Header.ID
		response.Header.Response = true
		response.Header.AuthoritativeAnswer = true
		response.Questions = append(response.Questions, q)
		response.Answers = append(response.Answers, pRec)

		resBuffer := packet.GetBuffer()
		resBuffer.HasNames = true
		response.Write(resBuffer)
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
	response := packet.NewDnsPacket()
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

	request := packet.NewDnsPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		s.Logger.Error("failed to parse packet", "error", err)
		return err
	}

	if len(request.Questions) == 0 {
		response := packet.NewDnsPacket()
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
	var clientOPT *packet.DnsRecord
	for _, res := range request.Resources {
		if res.Type == packet.OPT {
			clientOPT = &res
			maxSize = int(res.UDPPayloadSize)
			if maxSize < 512 { maxSize = 512 }
			// DO bit is the first bit of the Z field (TTL bits 15-0)
			dnssecOK = (res.Z & 0x8000) != 0
			break
		}
	}

	response := packet.NewDnsPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, q)

	// If query had EDNS, response MUST have EDNS
	if clientOPT != nil {
		opt := packet.DnsRecord{
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
			// DNSSEC: If DO bit is set, include NSEC record
			if dnssecOK {
				nsec, err := s.generateNSEC(ctx, zone, q.Name)
				if err == nil {
					response.Authorities = append(response.Authorities, nsec)
				}
			}
		} else {
			// Not authoritative for this zone
			response.Header.AuthoritativeAnswer = false
			response.Header.ResCode = 3
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

	// Handle Truncation
	for _, res := range request.Resources {
		if res.Type == packet.OPT {
			maxSize = int(res.UDPPayloadSize)
			if maxSize < 512 { maxSize = 512 }
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

func (s *Server) generateNSEC(ctx context.Context, zone *domain.Zone, queryName string) (packet.DnsRecord, error) {
	records, err := s.Repo.ListRecordsForZone(ctx, zone.ID)
	if err != nil { return packet.DnsRecord{}, err }

	master.SortRecordsCanonically(records)

	// Remove duplicate names (keep only one per unique name for NSEC)
	var uniqueNames []string
	seen := make(map[string]bool)
	for _, r := range records {
		if !seen[r.Name] {
			uniqueNames = append(uniqueNames, r.Name)
			seen[r.Name] = true
		}
	}

	// Find the record that "covers" the queryName
	// NSEC Name: owner name of record in zone
	// Next Name: next owner name in canonical order
	var ownerName, nextName string
	found := false
	for i := 0; i < len(uniqueNames); i++ {
		cmp := master.CompareNamesCanonically(queryName, uniqueNames[i])
		if cmp < 0 {
			// queryName is before uniqueNames[i]
			// The interval is [uniqueNames[i-1], uniqueNames[i]]
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
			// Exact match (NODATA case)
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
		// Wraps around to the start
		ownerName = uniqueNames[len(uniqueNames)-1]
		nextName = uniqueNames[0]
	}

	nsec := packet.DnsRecord{
		Name:     ownerName,
		Type:     packet.NSEC,
		Class:    1,
		TTL:      300,
		NextName: nextName,
		// Simplified bitmap: just signal A, NS, SOA, NSEC
		TypeBitMap: []byte{0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03}, 
	}

	return nsec, nil
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
	case packet.SOA:
		return domain.TypeSOA
	case packet.TXT:
		return domain.TypeTXT
	case packet.PTR:
		return domain.TypePTR
	case packet.ANY:
		return "" // ANY matches all types in our repo logic
	default:
		return ""
	}
}
