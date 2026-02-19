package server

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
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
	zones, errList := s.Repo.ListZones(ctx, "")
	if errList != nil {
		return
	}

	for _, z := range zones {
		if errAutomate := s.DNSSEC.AutomateLifecycle(ctx, z.ID); errAutomate != nil {
			s.Logger.Error("DNSSEC automation failed for zone", "zone", z.Name, "error", errAutomate)
		}
	}
}

func (s *Server) Run() error {
	s.Logger.Info("starting parallel server", "addr", s.Addr, "listeners", runtime.NumCPU())

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if errReuse := setReusePort(fd); errReuse != nil {
					s.Logger.Warn("failed to set reuse port", "error", errReuse)
				}
			})
		},
	}

	// 1. Parallel UDP
	started := 0
	for i := 0; i < runtime.NumCPU(); i++ {
		conn, errListen := lc.ListenPacket(context.Background(), "udp", s.Addr)
		if errListen != nil {
			s.Logger.Error("failed to start UDP listener", "id", i, "error", errListen)
			continue
		}
		started++
		go func(c net.PacketConn) {
			defer func() {
				if errClose := c.Close(); errClose != nil {
					s.Logger.Error("failed to close UDP connection", "error", errClose)
				}
			}()
			for {
				buf := make([]byte, 512)
				n, addr, errRead := c.ReadFrom(buf)
				if errRead != nil {
					continue
				}
				data := make([]byte, n)
				copy(data, buf[:n])
				s.udpQueue <- udpTask{addr: addr, data: data, conn: c}
			}
		}(conn)
	}

	if started == 0 {
		return fmt.Errorf("failed to start any UDP listeners on %s", s.Addr)
	}

	// 2. UDP Workers
	for i := 0; i < s.WorkerCount; i++ {
		go s.udpWorker()
	}

	// 3. TCP Listener
	tcpListener, errTCP := lc.Listen(context.Background(), "tcp", s.Addr)
	if errTCP == nil {
		go func() {
			defer func() {
				if errClose := tcpListener.Close(); errClose != nil {
					s.Logger.Error("failed to close TCP listener", "error", errClose)
				}
			}()
			for {
				conn, errAccept := tcpListener.Accept()
				if errAccept != nil {
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
		dotListener, errDoT := tls.Listen("tcp", dotAddr, s.TLSConfig)
		if errDoT == nil {
			s.Logger.Info("DNS over TLS (DoT) starting", "addr", dotAddr)
			go func() {
				defer func() {
					if errClose := dotListener.Close(); errClose != nil {
						s.Logger.Error("failed to close DoT listener", "error", errClose)
					}
				}()
				for {
					conn, errAccept := dotListener.Accept()
					if errAccept != nil {
						continue
					}
					go s.handleTCPConnection(conn)
				}
			}()
		}

		// 5. DoH Listener
		dohPort := os.Getenv("DOH_PORT")
		if dohPort == "" {
			dohPort = "443"
		}
		dohAddr := net.JoinHostPort(host, dohPort)
		mux := http.NewServeMux()
		mux.HandleFunc("/dns-query", s.handleDoH)
		dohServer := &http.Server{
			Addr:              dohAddr,
			Handler:           mux,
			TLSConfig:         s.TLSConfig,
			ReadHeaderTimeout: 5 * time.Second,
		}
		s.Logger.Info("DNS over HTTPS (DoH) starting", "addr", dohAddr)
		go func() {
			if errDoH := dohServer.ListenAndServeTLS("", ""); errDoH != nil {
				s.Logger.Error("DoH server failed", "error", errDoH)
			}
		}()
	}

	select {}
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var dnsMsg []byte
	var errDoH error

	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query().Get("dns")
		if query == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		dnsMsg, errDoH = base64.RawURLEncoding.DecodeString(query)
		if errDoH != nil {
			// Try with padding if raw fails
			dnsMsg, errDoH = base64.URLEncoding.DecodeString(query)
			if errDoH != nil {
				http.Error(w, "invalid base64", http.StatusBadRequest)
				return
			}
		}
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		dnsMsg, errDoH = io.ReadAll(r.Body)
		if errDoH != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if errHandle := s.handlePacket(dnsMsg, r.RemoteAddr, func(resp []byte) error {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return nil
	}); errHandle != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

func (s *Server) udpWorker() {
	for task := range s.udpQueue {
		s.handleUDPConnection(task.conn, task.addr, task.data)
	}
}

func (s *Server) handleUDPConnection(pc net.PacketConn, addr net.Addr, data []byte) {
	if errHandle := s.handlePacket(data, addr, func(resp []byte) error {
		_, errWrite := pc.WriteTo(resp, addr)
		return errWrite
	}); errHandle != nil {
		s.Logger.Error("failed to handle UDP packet", "error", errHandle)
	}
}

func (s *Server) handleTCPConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		lenBuf := make([]byte, 2)
		if _, errRead := io.ReadFull(conn, lenBuf); errRead != nil {
			return
		}
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
		data := make([]byte, packetLen)
		if _, errRead := io.ReadFull(conn, data); errRead != nil {
			return
		}

		// Check for AXFR/IXFR
		reqBuffer := packet.GetBuffer()
		reqBuffer.Load(data)
		request := packet.NewDNSPacket()
		if errFromBuf := request.FromBuffer(reqBuffer); errFromBuf == nil && len(request.Questions) > 0 {
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

		if errHandle := s.handlePacket(data, conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp)) // #nosec G115
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, errWrite := conn.Write(fullResp)
			return errWrite
		}); errHandle != nil {
			s.Logger.Error("Failed to handle TCP packet", "error", errHandle)
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

	records, errList := s.Repo.ListRecordsForZone(ctx, zone.ID)
	if errList != nil {
		s.Logger.Error("AXFR failed to list records", "zone", zone.ID, "error", errList)
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
	stream := make([]domain.Record, 0, len(otherRecords)+2)
	stream = append(stream, *soa)
	stream = append(stream, otherRecords...)
	stream = append(stream, *soa)

	s.Logger.Info("AXFR starting", "zone", zone.Name, "records", len(stream))

	for i, rec := range stream {
		pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
		if errConv != nil {
			s.Logger.Error("AXFR failed to convert record", "type", rec.Type, "error", errConv)
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
		if errWrite := response.Write(resBuffer); errWrite != nil {
			s.Logger.Error("AXFR failed to write response", "error", errWrite)
			packet.PutBuffer(resBuffer)
			continue
		}
		resData := resBuffer.Buf[:resBuffer.Position()]

		resLen := uint16(len(resData)) // #nosec G115
		fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
		if _, errW := conn.Write(fullResp); errW != nil {
			s.Logger.Error("AXFR connection broken", "error", errW)
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
	_ = response.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	_, _ = conn.Write(fullResp)
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
	if errParse := request.FromBuffer(reqBuffer); errParse != nil {
		s.Logger.Error("failed to parse packet", "error", errParse)
		return errParse
	}

	if request.Header.Opcode == packet.OpcodeUpdate {
		return s.handleUpdate(request, data, clientIP, sendFn)
	}

	if request.Header.Opcode == packet.OpcodeNotify {
		return s.handleNotify(request, clientIP, sendFn)
	}

	if len(request.Questions) == 0 {
		response := packet.NewDNSPacket()
		response.Header.ID = request.Header.ID
		response.Header.Response = true
		response.Header.ResCode = 4 // FORMERR
		resBuffer := packet.GetBuffer()
		defer packet.PutBuffer(resBuffer)
		_ = response.Write(resBuffer)
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
		// Use crypto/rand for simulation jitter (safe for G404)
		var b [8]byte
		_, _ = crand.Read(b[:])
		jitter := float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64)
		time.Sleep(time.Duration(float64(s.SimulateDBLatency) * (0.5 + jitter)))
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
	records, errRepo := s.Repo.GetRecords(ctx, q.Name, qTypeStr, clientIP)
	if errRepo == nil && len(records) > 0 {
		for _, rec := range records {
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				response.Answers = append(response.Answers, pRec)
			}
		}
	} else if zone != nil {
		// Try wildcard matching if no direct records found
		labels := strings.Split(strings.TrimSuffix(q.Name, "."), ".")
		for i := 0; i < len(labels)-1; i++ {
			wildcardName := "*." + strings.Join(labels[i+1:], ".") + "."
			wildcardRecords, errWildcard := s.Repo.GetRecords(ctx, wildcardName, qTypeStr, clientIP)
			if errWildcard == nil && len(wildcardRecords) > 0 {
				source = "wildcard"
				for _, rec := range wildcardRecords {
					rec.Name = q.Name // RFC: Rewrite wildcard to query name
					pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
					if errConv == nil {
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
				pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
				if errConv == nil {
					response.Authorities = append(response.Authorities, pRec)
				}
			}

			// DNSSEC: If DO bit is set, include NSEC or NSEC3 record
			if dnssecOK {
				// Check for NSEC3PARAM to decide between NSEC and NSEC3
				nsec3params, _ := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
				if len(nsec3params) > 0 {
					nsec3, errNsec := s.generateNSEC3(ctx, zone, q.Name)
					if errNsec == nil {
						response.Authorities = append(response.Authorities, nsec3)
					}
				} else {
					nsec, errNsec := s.generateNSEC(ctx, zone, q.Name)
					if errNsec == nil {
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
					response.Resources[i].AddEDE(packet.EdeOther, "")
				}
			}
		}
	} else if zone != nil {
		// 4. Populate Authority Section (NS records)
		nsRecords, _ := s.Repo.GetRecords(ctx, zone.Name, domain.TypeNS, clientIP)
		for _, rec := range nsRecords {
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				response.Authorities = append(response.Authorities, pRec)

				// 5. Populate Additional Section (Glue records)
				glueRecords, _ := s.Repo.GetRecords(ctx, pRec.Host, domain.TypeA, clientIP)
				for _, gRec := range glueRecords {
					gpRec, errGlue := repository.ConvertDomainToPacketRecord(gRec)
					if errGlue == nil {
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
	_ = response.Write(resBuffer)

	if resBuffer.Position() > maxSize {
		response.Header.TruncatedMessage = true
		response.Answers = nil
		response.Authorities = nil
		response.Resources = nil
		resBuffer.Reset()
		resBuffer.HasNames = true
		_ = response.Write(resBuffer)
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
	s.Logger.Info("received NOTIFY", "zone", request.Questions[0].Name, "from", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeNotify
	response.Header.AuthoritativeAnswer = true
	if len(request.Questions) > 0 {
		response.Questions = append(response.Questions, request.Questions[0])
	}

	// TODO: If we are a slave, trigger refresh/IXFR here.
	// For now, we just acknowledge.

	response.Header.ResCode = packet.RcodeNoError
	return s.sendUpdateResponse(response, sendFn)
}

func (s *Server) handleUpdate(request *packet.DNSPacket, rawData []byte, clientIP string, sendFn func([]byte) error) error {
	s.Logger.Info("handling dynamic update", "id", request.Header.ID, "client", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeUpdate

	// 1. Validate TSIG if present
	if request.TSIGStart != -1 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Warn("update failed: unknown TSIG key", "key", tsig.Name)
			response.Header.ResCode = packet.RcodeNotAuth
			return s.sendUpdateResponse(response, sendFn)
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, secret); errVerify != nil {
			s.Logger.Warn("update failed: TSIG verification failed", "error", errVerify)
			response.Header.ResCode = packet.RcodeNotAuth
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 2. Validate Zone Section (ZOCOUNT must be 1)
	if len(request.Questions) != 1 {
		s.Logger.Warn("update failed: ZOCOUNT != 1", "count", len(request.Questions))
		response.Header.ResCode = packet.RcodeFormErr
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
		response.Header.ResCode = packet.RcodeNotAuth
		return s.sendUpdateResponse(response, sendFn)
	}

	// 2. Prerequisite Checks (PRCOUNT)
	for _, pr := range request.Answers {
		if errPrereq := s.checkPrerequisite(ctx, pr); errPrereq != nil {
			s.Logger.Warn("update failed: prerequisite mismatch", "pr", pr.Name, "error", errPrereq)
			var uErr updateError
			if errors.As(errPrereq, &uErr) {
				response.Header.ResCode = uint8(uErr.rcode) // #nosec G115
			} else {
				response.Header.ResCode = packet.RcodeServFail
			}
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 3. Perform Updates (UPCOUNT)
	var newSerial uint32
	changes := make([]domain.ZoneChange, 0, len(request.Authorities))

	for _, up := range request.Authorities {
		if errUpd := s.applyUpdate(ctx, dbZone, up); errUpd != nil {
			s.Logger.Error("update failed: failed to apply record change", "up", up.Name, "error", errUpd)
			response.Header.ResCode = packet.RcodeServFail
			return s.sendUpdateResponse(response, sendFn)
		}

		// Record change for IXFR (using crand for secure ID)
		var b [8]byte
		_, _ = crand.Read(b[:])
		randomPart := binary.LittleEndian.Uint64(b[:])
		change := domain.ZoneChange{
			ID:        fmt.Sprintf("%d-%x", time.Now().UnixNano(), randomPart),
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
				_, _ = fmt.Sscanf(parts[2], "%d", &newSerial)
				newSerial++
				parts[2] = fmt.Sprintf("%d", newSerial)
				soa.Content = strings.Join(parts, " ")

				// Delete old SOA and create new one (simplified update)
				_ = s.Repo.DeleteRecord(ctx, soa.ID, dbZone.ID)
				_ = s.Repo.CreateRecord(ctx, &soa)

				// Persist changes with the new serial
				for i := range changes {
					changes[i].Serial = newSerial
					_ = s.Repo.RecordZoneChange(ctx, &changes[i])
				}
			}
		}
	}

	// 5. Success
	response.Header.ResCode = packet.RcodeNoError
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
	_, _ = fmt.Sscanf(strings.Fields(currentSOA.Content)[2], "%d", &currentSerial)

	if clientSerial == currentSerial {
		// Client is up to date, just send current SOA
		s.Logger.Info("IXFR client is up to date", "zone", zone.Name, "serial", clientSerial)
		pSOA, _ := repository.ConvertDomainToPacketRecord(currentSOA)
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)
		return
	}

	// Fetch changes since clientSerial
	changes, errChanges := s.Repo.ListZoneChanges(ctx, zone.ID, clientSerial)
	if errChanges != nil || len(changes) == 0 {
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

				s.sendIXFRDiff(conn, request.Header.ID, tempSOA, deletions, additions)
				deletions = nil
				additions = nil
			}
			currentDiffSerial = c.Serial
		}

		var ttl uint32
		// Explicit range check for G115
		if c.TTL >= 0 && int64(c.TTL) <= math.MaxUint32 {
			ttl = uint32(c.TTL) // #nosec G115
		}

		pRec := packet.DNSRecord{
			Name:  c.Name,
			Type:  packet.QueryType(master.RecordTypeToQueryType(c.Type)),
			TTL:   ttl,
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
		s.sendIXFRDiff(conn, request.Header.ID, tempSOA, deletions, additions)
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
			sigs, errSign := s.DNSSEC.SignRRSet(ctx, zone.Name, zone.ID, group)
			if errSign == nil {
				response.Answers = append(response.Answers, sigs...)
			}
		}
	}
	// Sign Authorities
	if len(response.Authorities) > 0 {
		groups := s.groupRecords(response.Authorities)
		for _, group := range groups {
			sigs, errSign := s.DNSSEC.SignRRSet(ctx, zone.Name, zone.ID, group)
			if errSign == nil {
				response.Authorities = append(response.Authorities, sigs...)
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

	res := make([][]packet.DNSRecord, 0, len(keys))
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
	_ = resp.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	_, _ = conn.Write(fullResp)
	packet.PutBuffer(resBuffer)
}

func (s *Server) sendIXFRDiff(conn net.Conn, id uint16, soa packet.DNSRecord, deletions, additions []packet.DNSRecord) {
	// 1. Send Old SOA + Deletions
	resp := packet.NewDNSPacket()
	resp.Header.ID = id
	resp.Header.Response = true
	resp.Answers = append(resp.Answers, soa)
	resp.Answers = append(resp.Answers, deletions...)

	resBuffer := packet.GetBuffer()
	_ = resp.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData)) // #nosec G115
	_, _ = conn.Write(append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...))
	packet.PutBuffer(resBuffer)

	// 2. Send New SOA + Additions
	resp = packet.NewDNSPacket()
	resp.Header.ID = id
	resp.Header.Response = true
	resp.Answers = append(resp.Answers, soa)
	resp.Answers[0].Serial++
	resp.Answers = append(resp.Answers, additions...)

	resBuffer = packet.GetBuffer()
	_ = resp.Write(resBuffer)
	resData = resBuffer.Buf[:resBuffer.Position()]
	resLen = uint16(len(resData)) // #nosec G115
	_, _ = conn.Write(append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...))
	packet.PutBuffer(resBuffer)
}

func (s *Server) sendUpdateResponse(resp *packet.DNSPacket, sendFn func([]byte) error) error {
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	_ = resp.Write(resBuffer)
	return sendFn(resBuffer.Buf[:resBuffer.Position()])
}

type updateError struct {
	rcode int
	msg   string
}

func (e updateError) Error() string { return e.msg }

func (s *Server) checkPrerequisite(ctx context.Context, pr packet.DNSRecord) error {
	qTypeStr := queryTypeToRecordType(pr.Type)
	records, errRecs := s.Repo.GetRecords(ctx, pr.Name, qTypeStr, "")
	if errRecs != nil {
		return updateError{rcode: int(packet.RcodeServFail), msg: "failed to fetch records for prerequisite check"}
	}

	switch pr.Class {
	case 255: // ANY
		if pr.Type == 255 { // ANY
			if len(records) == 0 {
				return updateError{rcode: int(packet.RcodeNxDomain), msg: "name not in use"}
			}
		} else {
			if len(records) == 0 {
				return updateError{rcode: int(packet.RcodeNxRRSet), msg: "rrset does not exist"}
			}
		}
	case 254: // NONE
		if pr.Type == 255 { // ANY
			if len(records) > 0 {
				return updateError{rcode: int(packet.RcodeYxDomain), msg: "name in use"}
			}
		} else {
			if len(records) > 0 {
				return updateError{rcode: int(packet.RcodeYxRRSet), msg: "rrset exists"}
			}
		}
	default:
		if len(records) == 0 {
			return updateError{rcode: int(packet.RcodeNxRRSet), msg: "rrset does not exist"}
		}
	}

	return nil
}

// applyUpdate processes a single record update from an RFC 2136 UPDATE message.
// It maps the DNS record class to the appropriate repository operation:
//   - Class ANY (255): Deletes an entire RRset (by name or name+type).
//   - Class NONE (254): Deletes a specific RR (must match name, type, and RDATA).
//   - Default Class (IN): Adds or replaces a record.
func (s *Server) applyUpdate(ctx context.Context, zone *domain.Zone, up packet.DNSRecord) error {
	// Standardize name for database lookups to ensure consistency.
	upName := up.Name
	if !strings.HasSuffix(upName, ".") {
		upName += "."
	}

	switch up.Class {
	case 255: // ANY: Delete RRset (RFC 2136 Section 2.5.2)
		if up.Type == 255 { // Type ANY: Delete all records for this name
			return s.Repo.DeleteRecordsByName(ctx, zone.ID, upName)
		}
		// Delete all records of a specific type for this name
		qTypeStr := queryTypeToRecordType(up.Type)
		return s.Repo.DeleteRecordsByNameAndType(ctx, zone.ID, upName, qTypeStr)

	case 254: // NONE: Delete specific record (RFC 2136 Section 2.5.4)
		qTypeStr := queryTypeToRecordType(up.Type)
		dRec, errConv := repository.ConvertPacketRecordToDomain(up, zone.ID)
		if errConv != nil {
			return errConv
		}
		// Matches name, type, and content (RDATA)
		return s.Repo.DeleteRecordSpecific(ctx, zone.ID, upName, qTypeStr, dRec.Content)

	default: // Add record (RFC 2136 Section 2.5.1)
		dRec, errConv := repository.ConvertPacketRecordToDomain(up, zone.ID)
		if errConv != nil {
			return errConv
		}
		dRec.Name = upName
		if dRec.ID == "" {
			// Generate a cryptographically secure ID for new records.
			var bid [16]byte
			_, _ = crand.Read(bid[:])
			dRec.ID = fmt.Sprintf("%d-%x", time.Now().UnixNano(), bid)
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

	dbZone, errZone := s.Repo.GetZone(ctx, zoneName)
	if errZone != nil || dbZone == nil {
		return
	}

	nsRecords, errNS := s.Repo.GetRecords(ctx, zoneName, domain.TypeNS, "")
	if errNS != nil {
		return
	}

	for _, ns := range nsRecords {
		ips, errIPs := s.Repo.GetIPsForName(ctx, ns.Content, "")
		if errIPs != nil || len(ips) == 0 {
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
			// Use crand for secure NOTIFY ID (G404)
			var bid [2]byte
			_, _ = crand.Read(bid[:])
			notify.Header.ID = binary.LittleEndian.Uint16(bid[:])

			notify.Header.Opcode = packet.OpcodeNotify
			notify.Header.AuthoritativeAnswer = true
			notify.Questions = append(notify.Questions, packet.DNSQuestion{
				Name:  zoneName,
				QType: packet.SOA,
			})

			buf := packet.GetBuffer()
			_ = notify.Write(buf)
			data := buf.Buf[:buf.Position()]

			conn, errDial := net.Dial("udp", targetAddr)
			if errDial == nil {
				_, _ = conn.Write(data)
				_ = conn.Close()
			}
			packet.PutBuffer(buf)
		}
	}
}

func (s *Server) generateNSEC(ctx context.Context, zone *domain.Zone, queryName string) (packet.DNSRecord, error) {
	records, errZoneRecs := s.Repo.ListRecordsForZone(ctx, zone.ID)
	if errZoneRecs != nil {
		return packet.DNSRecord{}, errZoneRecs
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
	params, errParams := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
	if errParams != nil || len(params) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no NSEC3PARAM")
	}

	parts := strings.Fields(params[0].Content)
	if len(parts) < 4 {
		return packet.DNSRecord{}, fmt.Errorf("invalid NSEC3PARAM")
	}

	var alg, flags uint8
	var iterations uint16
	_, _ = fmt.Sscanf(parts[0], "%d", &alg)
	_, _ = fmt.Sscanf(parts[1], "%d", &flags)
	_, _ = fmt.Sscanf(parts[2], "%d", &iterations)
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

	hashes := make([]hashEntry, 0, len(ownerNames))
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

type hashEntry struct {
	name string
	hash []byte
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
		bits[byteIdx] |= (1 << bitIdx) // #nosec G602
		if int(byteIdx) > maxType {
			maxType = int(byteIdx)
		}
	}

	res := make([]byte, 0, 2 + (maxType + 1))
	res = append(res, 0, byte(maxType + 1))
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
