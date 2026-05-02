package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/config"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/core/utils"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
	"github.com/quic-go/quic-go"
)

// ClassCHAOS is the DNS class for server identity and metadata.
const ClassCHAOS = 3

// cacheLockShardCount is the number of shards for per-key cache locks.
// Using sharded locking avoids unbounded map growth while providing per-key granularity.
const cacheLockShardCount = 256

type cacheLockShard struct {
	mu sync.Mutex
}

func (s *cacheLockShard) Lock()   { s.mu.Lock() }
func (s *cacheLockShard) Unlock() { s.mu.Unlock() }

type cacheLockTable [cacheLockShardCount]cacheLockShard

var globalCacheLocks cacheLockTable

func fnv32(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key)) // #nosec G104
	return h.Sum32()
}

func (t *cacheLockTable) lockKey(key string) *cacheLockShard {
	return &t[fnv32(key)%cacheLockShardCount]
}

// Server is the core DNS server that handles incoming queries,
// zone transfers (AXFR/IXFR), updates (RFC 2136), and NOTIFY (RFC 1996).
type Server struct {
	Addr             string
	Repo             ports.DNSRepository
	Cache            *DNSCache
	Redis            *RedisCache
	DNSSEC           *services.DNSSECService
	DNSSECValidator  *services.DNSSECValidator
	DNSSECMode       string // "disabled", "ad-bit-only", "strict"
	DNSSECConfig     *config.DNSSECConfig
	dnskeyCache      *DNSCache // cached DNSKEY records for DNSSEC validation
	WorkerCount      int
	udpQueue         chan udpTask
	Logger           *slog.Logger
	queryFn          func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error)
	limiter          *rateLimiter
	TsigKeys         map[string][]byte
	NodeID           string
	RecursionEnabled bool
	CookieSecret     []byte

	// Testing/Chaos flags
	SimulateDBLatency  time.Duration
	NotifyPortOverride int
	DisableAsync       bool // If true, NOTIFY and UPDATE handlers won't spawn goroutines

	// TLS Config for DoT, DoH, and DoQ
	TLSConfig *tls.Config
	DoQAddr  string // DNS-over-QUIC listen address (default ":853")

	// Listener handles for graceful shutdown
	tcpListener net.Listener
	dotListener  net.Listener
	dohServer    *http.Server
	doqListener *quic.Listener

	// lifecycleCtx is a long-lived context for background workers.
	// cancel cancels the lifecycleCtx.
	// done is closed when the Server shuts down to signal workers to exit.
	lifecycleCtx context.Context
	cancel       context.CancelFunc
	done         chan struct{}
	wg           sync.WaitGroup
}

type udpTask struct {
	addr net.Addr
	data []byte
	conn net.PacketConn
}

// NewServer creates a new DNS server instance.
func NewServer(addr string, repo ports.DNSRepository, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}

	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		h, _ := os.Hostname()
		if h != "" {
			nodeID = h
		} else {
			nodeID = "unknown-node"
		}
	}

	recursion := os.Getenv("RECURSION_ENABLED") == "true"

	s := &Server{
		Addr:             addr,
		Repo:             repo,
		WorkerCount:      runtime.NumCPU() * 32, // High concurrency tuning
		udpQueue:         make(chan udpTask, 50000),
		Logger:           logger,
		limiter:          newRateLimiter(500000, 200000, 1000000),
		TsigKeys:         make(map[string][]byte),
		NodeID:           nodeID,
		RecursionEnabled: recursion,
		CookieSecret:     make([]byte, 32),
	}
	s.lifecycleCtx, s.cancel = context.WithCancel(context.Background())
	s.done = make(chan struct{})
	_, _ = crand.Read(s.CookieSecret)
	s.queryFn = s.sendQuery

	// Initialize caches with done channel for graceful shutdown
	s.Cache = NewDNSCache(s.done, &s.wg)
	s.dnskeyCache = NewDNSCache(s.done, &s.wg)
	s.DNSSEC = services.NewDNSSECService(repo)

	// Periodic cleanup of rate limiter buckets
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.limiter.CleanupLoop(s.done)
	}()

	// Background DNSSEC automation: Run every hour
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				if s.Repo != nil && s.DNSSEC != nil {
					s.automateDNSSEC()
				}
			}
		}
	}()

	return s
}

func (s *Server) generateServerCookie(clientCookie []byte, clientIP string) []byte {
	h := hmac.New(sha256.New, s.CookieSecret)
	h.Write(clientCookie)
	h.Write([]byte(clientIP))
	return h.Sum(nil)[:16] // Return 16 bytes of server cookie
}

func (s *Server) padResponse(response *packet.DNSPacket, blockSize int) {
	// Find OPT record
	var opt *packet.DNSRecord
	for i := range response.Resources {
		if response.Resources[i].Type == packet.OPT {
			opt = &response.Resources[i]
			break
		}
	}

	if opt == nil {
		// PADDING requires an OPT record.
		return
	}

	// Remove existing padding if any to avoid double padding
	for i, o := range opt.Options {
		if o.Code == packet.EdnsOptionPadding {
			opt.Options = append(opt.Options[:i], opt.Options[i+1:]...)
			break
		}
	}

	// Calculate current size with compression enabled
	buf := packet.GetBuffer()
	defer packet.PutBuffer(buf)
	buf.HasNames = true
	_ = response.Write(buf)
	currentSize := buf.Position()

	// The Padding option itself adds 4 bytes (code + length)
	overhead := 4
	needed := blockSize - (currentSize+overhead)%blockSize
	if (currentSize+overhead)%blockSize == 0 {
		needed = 0
	}
	
	padding := make([]byte, needed)
	opt.SetOption(packet.EdnsOptionPadding, padding)
}

func (s *Server) automateDNSSEC() {
	ctx := s.lifecycleCtx
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

func (s *Server) startInvalidationListener(ctx context.Context) {
	pubsub := s.Redis.Subscribe(ctx)
	defer func() {
		if errClose := pubsub.Close(); errClose != nil {
			s.Logger.Error("failed to close pubsub", "error", errClose)
		}
	}()

	ch := pubsub.Channel()
	s.Logger.Info("started global cache invalidation listener")

	for {
		select {
		case <-ctx.Done():
			s.Logger.Info("stopping global cache invalidation listener")
			return
		case msg := <-ch:
			// msg.Payload format is "name:type"
			s.Logger.Debug("received cache invalidation event", "key", msg.Payload)

			// Standardize key for L1 cache lookup (lowercase name)
			parts := strings.SplitN(msg.Payload, ":", 2)
			if len(parts) != 2 {
				s.Logger.Warn("malformed cache invalidation payload, dropping", "payload", msg.Payload)
				continue
			}

			qType := packet.RecordTypeToQueryType(domain.RecordType(parts[1]))
			l1Key := fmt.Sprintf("%s:%d", strings.ToLower(parts[0]), qType)
			if s.Cache == nil {
				s.Logger.Warn("cache is nil, pushing to DLQ", "key", l1Key)
				if errDLQ := s.Redis.PushToDLQ(ctx, msg.Payload); errDLQ != nil {
					s.Logger.Error("failed to push nil-cache message to DLQ", "error", errDLQ)
				}
				continue
			}

			s.Cache.Invalidate(l1Key)
		}
	}
}

// dlqRetryWorker processes messages from the dead letter queue with retry logic.
// It runs until the context is canceled.
func (s *Server) dlqRetryWorker(ctx context.Context) {
	s.Logger.Info("starting DLQ retry worker")

	for {
		select {
		case <-ctx.Done():
			s.Logger.Info("stopping DLQ retry worker")
			return
		case <-time.After(5 * time.Second):
			// Continue to process DLQ after backoff
		}

		msg, err := s.Redis.PopFromDLQ(ctx, 0)
		if err != nil {
			if ctx.Err() != nil {
				return // Context canceled
			}
			s.Logger.Error("failed to pop from DLQ", "error", err)
			continue
		}
		if msg == "" {
			continue // No messages
		}

		s.Logger.Debug("retrying DLQ message", "msg", msg)
		parts := strings.SplitN(msg, ":", 2)
		if len(parts) != 2 {
			s.Logger.Warn("DLQ message malformed, dropping", "msg", msg)
			continue
		}

		qType := packet.RecordTypeToQueryType(domain.RecordType(parts[1]))
		l1Key := fmt.Sprintf("%s:%d", strings.ToLower(parts[0]), qType)

		if s.Cache != nil {
			s.Cache.Invalidate(l1Key)
			s.Logger.Debug("DLQ message processed successfully", "key", l1Key)
		} else {
			// Cache still nil, log and drop (malformed messages from startInvalidationListener
			// are already dropped there; if we get here with nil cache, something is wrong)
			s.Logger.Warn("cache still nil, dropping DLQ message", "key", l1Key)
		}
	}
}


// udpReadDeadline is the read deadline set on UDP sockets to allow periodic
// re-checking of the shutdown signal (s.done). Without this, ReadFrom blocks
// indefinitely and goroutines don't exit promptly on cancellation.
const udpReadDeadline = 500 * time.Millisecond
// Run starts the DNS server and blocks until the context is canceled.
func (s *Server) Run(ctx context.Context) error {
	s.Logger.Info("starting parallel server", "addr", s.Addr, "listeners", runtime.NumCPU())

	// Deferred shutdown signals all goroutines to exit when Run returns.
	// Uses a deferred function to ensure cleanup runs even on early return.
	// The context parameter satisfies the contextcheck linter but is not used
	// because s.cancel is bound to lifecycleCtx at server creation.
	defer func(_ context.Context) {
		s.cancel()
		close(s.done) // Signal all workers to exit (goroutines check s.done and exit via wg.Done)
		// Close listeners to unblock Accept/ReadFrom calls
		if s.tcpListener != nil {
			_ = s.tcpListener.Close()
		}
		if s.dotListener != nil {
			_ = s.dotListener.Close()
		}
		if s.dohServer != nil {
			shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_ = s.dohServer.Shutdown(shutdownCtx)
		}
		if s.doqListener != nil {
			_ = s.doqListener.Close()
		}
	}(ctx)

	// Initialize DNSSECValidator from config if provided
	if s.DNSSECConfig != nil {
		anchors, err := s.DNSSECConfig.ToMap()
		if err != nil {
			s.Logger.Warn("failed to parse DNSSEC trust anchors", "error", err)
		} else {
			s.DNSSECValidator = services.NewDNSSECValidator(anchors)
			s.Logger.Info("DNSSEC validator initialized", "zones", len(anchors))
		}
		if s.DNSSECMode == "" && s.DNSSECConfig.Mode != "" {
			s.DNSSECMode = s.DNSSECConfig.Mode
		}
	}

	// Start cache invalidation listener if Redis is enabled
	if s.Redis != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.startInvalidationListener(ctx)
		}()

		// Start DLQ retry worker
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dlqRetryWorker(ctx)
		}()
	}

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
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
		conn, errListen := lc.ListenPacket(ctx, "udp", s.Addr)
		if errListen != nil {
			s.Logger.Error("failed to start UDP listener", "id", i, "error", errListen)
			continue
		}
		started++
		s.wg.Add(1)
		go func(c net.PacketConn) {
			defer func() {
				_ = c.Close()
			}()
			defer s.wg.Done()
			// Set read deadline so select can re-check s.done periodically
			_ = c.SetReadDeadline(time.Now().Add(udpReadDeadline))
			buf := make([]byte, 512)
			for {
				select {
				case <-s.done:
					return
				default:
					n, addr, errRead := c.ReadFrom(buf)
					if errRead != nil {
						if errors.Is(errRead, net.ErrClosed) {
							return
						}
						// Refresh deadline to allow re-check of s.done
						_ = c.SetReadDeadline(time.Now().Add(udpReadDeadline))
						continue
					}
					data := make([]byte, n)
					copy(data, buf[:n])
					s.udpQueue <- udpTask{addr: addr, data: data, conn: c}
				}
			}
		}(conn)
	}

	if started == 0 {
		return fmt.Errorf("failed to start any UDP listeners on %s", s.Addr)
	}

	// 2. UDP Workers
	for i := 0; i < s.WorkerCount; i++ {
		s.wg.Add(1)
		go s.udpWorker()
	}

	// 3. TCP Listener
	tcpListener, errTCP := lc.Listen(ctx, "tcp", s.Addr)
	if errTCP == nil {
		s.tcpListener = tcpListener
		s.wg.Add(1)
		go func() {
			defer func() {
				_ = s.tcpListener.Close()
			}()
			defer s.wg.Done()
			for {
				conn, errAccept := tcpListener.Accept()
				if errAccept != nil {
					if errors.Is(errAccept, net.ErrClosed) {
						return
					}
					continue
				}
				go s.handleTCPConnection(s.lifecycleCtx, conn)
			}
		}()
	}

	// 4. DoT Listener (Port 853)
	if s.TLSConfig != nil {
		host, _, _ := net.SplitHostPort(s.Addr)
		dotAddr := net.JoinHostPort(host, "853")
		dotListener, errDoT := tls.Listen("tcp", dotAddr, s.TLSConfig)
		if errDoT == nil {
			s.dotListener = dotListener
			s.Logger.Info("DNS over TLS (DoT) starting", "addr", dotAddr)
			s.wg.Add(1)
			go func() {
				defer func() {
					_ = s.dotListener.Close()
				}()
				defer s.wg.Done()
				for {
					conn, errAccept := s.dotListener.Accept()
					if errAccept != nil {
						if errors.Is(errAccept, net.ErrClosed) {
							return
						}
						continue
					}
					go s.handleTCPConnection(s.lifecycleCtx, conn)
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
		s.dohServer = dohServer
		s.Logger.Info("DNS over HTTPS (DoH) starting", "addr", dohAddr)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if errDoH := dohServer.ListenAndServeTLS("", ""); errDoH != nil && !errors.Is(errDoH, http.ErrServerClosed) {
				s.Logger.Error("DoH server failed", "error", errDoH)
			}
		}()
	}

	// 6. DoQ Listener (Port 853)
	if s.DoQAddr != "" {
		if s.TLSConfig == nil {
			s.Logger.Error("DNS over QUIC (DoQ) skipped", "reason", "TLS config required but not provided", "addr", s.DoQAddr)
		} else {
			quicListener, errDoQ := s.setupDoQListener(s.DoQAddr)
			if errDoQ != nil {
				s.Logger.Error("DNS over QUIC (DoQ) listener setup failed", "error", errDoQ, "addr", s.DoQAddr)
			} else {
				s.doqListener = quicListener
				s.Logger.Info("DNS over QUIC (DoQ) starting", "addr", s.DoQAddr)
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					s.handleDoQListener(s.lifecycleCtx, quicListener)
				}()
			}
		}
	}

	<-ctx.Done()
	return nil // async shutdown handles cleanup in background
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

	if errHandle := s.handlePacket(r.Context(), dnsMsg, r.RemoteAddr, func(resp []byte) error {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return nil
	}, "doh"); errHandle != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

func (s *Server) udpWorker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case task := <-s.udpQueue:
			metrics.ActiveWorkers.Inc()
			s.handleUDPConnection(s.lifecycleCtx, task.conn, task.addr, task.data)
			metrics.ActiveWorkers.Dec()
		}
	}
}

func (s *Server) handleUDPConnection(ctx context.Context, pc net.PacketConn, addr net.Addr, data []byte) {
	if errHandle := s.handlePacket(ctx, data, addr, func(resp []byte) error {
		_, errWrite := pc.WriteTo(resp, addr)
		return errWrite
	}, "udp"); errHandle != nil {
		s.Logger.Error("failed to handle UDP packet", "error", errHandle)
	}
}

func (s *Server) handleTCPConnection(ctx context.Context, conn net.Conn) {
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
				s.handleAXFR(ctx, conn, request, data)
				packet.PutBuffer(reqBuffer)
				continue
			}
			if request.Questions[0].QType == packet.IXFR {
				s.handleIXFR(ctx, conn, request, data)
				packet.PutBuffer(reqBuffer)
				continue
			}
		}
		packet.PutBuffer(reqBuffer)

		if errHandle := s.handlePacket(ctx, data, conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp)) // #nosec G115
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, errWrite := conn.Write(fullResp)
			return errWrite
		}, "tcp"); errHandle != nil {
			s.Logger.Error("Failed to handle TCP packet", "error", errHandle)
		}
	}
}

func (s *Server) handleAXFR(ctx context.Context, conn net.Conn, request *packet.DNSPacket, rawData []byte) {
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Validate TSIG if present
	if request.TSIGStart != -1 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Warn("AXFR failed: unknown TSIG key", "key", tsig.Name, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, secret); errVerify != nil {
			s.Logger.Warn("AXFR failed: TSIG verification failed", "error", errVerify, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	zone, _ := s.Repo.GetZone(ctx, q.Name)
	if zone == nil {
		s.Logger.Warn("AXFR requested for non-existent zone", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 3) // NXDOMAIN
		return
	}

	iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
	if errIter != nil {
		s.Logger.Error("AXFR failed to open record stream", "zone", zone.ID, "error", errIter)
		s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
		return
	}
	defer func() { _ = iter.Close() }()

	// First pass: find SOA record
	var soa domain.Record
	var foundSOA bool
	for iter.Next() {
		rec := iter.Record()
		if rec.Type == domain.TypeSOA {
			soa = rec
			foundSOA = true
			break
		}
	}
	if err := iter.Err(); err != nil {
		s.Logger.Error("AXFR failed during SOA lookup", "zone", zone.ID, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}
	if !foundSOA {
		s.Logger.Error("AXFR failed: zone has no SOA", "zone", zone.Name)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	s.Logger.Info("AXFR starting", "zone", zone.Name)

	// Stream SOA first
	s.sendAXFRRecord(conn, request.Header.ID, q, soa, 0)

	// Stream all non-SOA records
	index := 1
	for iter.Next() {
		rec := iter.Record()
		if rec.Type == domain.TypeSOA {
			continue
		}
		s.sendAXFRRecord(conn, request.Header.ID, q, rec, index)
		index++
	}
	if err := iter.Err(); err != nil {
		s.Logger.Error("AXFR failed during record streaming", "zone", zone.ID, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	// Stream SOA last
	s.sendAXFRRecord(conn, request.Header.ID, q, soa, index)
	s.Logger.Info("AXFR completed", "zone", zone.Name)
}

// sendAXFRRecord converts a domain.Record to a packet record and sends it over TCP.
func (s *Server) sendAXFRRecord(conn net.Conn, id uint16, q packet.DNSQuestion, rec domain.Record, index int) {
	pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
	if errConv != nil {
		s.Logger.Error("AXFR failed to convert record", "type", rec.Type, "error", errConv)
		return
	}

	response := packet.NewDNSPacket()
	response.Header.ID = id
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, q)
	response.Answers = append(response.Answers, pRec)

	resBuffer := packet.GetBuffer()
	resBuffer.HasNames = true
	if errWrite := response.Write(resBuffer); errWrite != nil {
		s.Logger.Error("AXFR failed to write response", "error", errWrite)
		packet.PutBuffer(resBuffer)
		return
	}
	resData := resBuffer.Buf[:resBuffer.Position()]

	resLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	if _, errW := conn.Write(fullResp); errW != nil {
		s.Logger.Error("AXFR connection broken", "error", errW)
		packet.PutBuffer(resBuffer)
		return
	}
	s.Logger.Debug("AXFR sent packet", "index", index, "type", pRec.Type)
	packet.PutBuffer(resBuffer)
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

func (s *Server) handlePacket(ctx context.Context, data []byte, srcAddr interface{}, sendFn func([]byte) error, protocol string) error {
	start := time.Now()
	defer func() {
		metrics.QueryDuration.WithLabelValues("total").Observe(time.Since(start).Seconds())
	}()

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

	// Default labels for metrics
	qTypeLabel := "UNKNOWN"
	if len(request.Questions) > 0 {
		qTypeLabel = request.Questions[0].QType.String()
	}

	if request.Header.Opcode == packet.OpcodeUpdate {
		err := s.handleUpdate(ctx, request, data, clientIP, sendFn)
		rcode := "0"
		if err == nil {
			rcode = fmt.Sprintf("%d", request.Header.ResCode)
		}
		metrics.QueriesTotal.WithLabelValues("UPDATE", rcode, protocol).Inc()
		return err
	}

	if request.Header.Opcode == packet.OpcodeNotify {
		err := s.handleNotify(ctx, request, clientIP, sendFn)
		metrics.QueriesTotal.WithLabelValues("NOTIFY", "0", protocol).Inc()
		return err
	}

	if len(request.Questions) == 0 {
		response := packet.NewDNSPacket()
		response.Header.ID = request.Header.ID
		response.Header.Response = true
		response.Header.ResCode = 4 // FORMERR
		metrics.QueriesTotal.WithLabelValues("NONE", "4", protocol).Inc()
		resBuffer := packet.GetBuffer()
		defer packet.PutBuffer(resBuffer)
		_ = response.Write(resBuffer)
		return sendFn(resBuffer.Buf[:resBuffer.Position()])
	}

	q := request.Questions[0]
	// 1. Handle CHAOS class queries for node identity (NSID readiness)
	if q.QClass == ClassCHAOS {
		if strings.ToLower(q.Name) == "id.server." || strings.ToLower(q.Name) == "hostname.bind." {
			response := packet.NewDNSPacket()
			response.Header.ID = request.Header.ID
			response.Header.Response = true
			response.Header.AuthoritativeAnswer = true
			response.Questions = append(response.Questions, q)

			txtRec := packet.DNSRecord{
				Name:  q.Name,
				Type:  packet.TXT,
				Class: ClassCHAOS,
				TTL:   0,
				Txt:   s.NodeID,
			}
			response.Answers = append(response.Answers, txtRec)

			metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
			resBuffer := packet.GetBuffer()
			defer packet.PutBuffer(resBuffer)
			_ = response.Write(resBuffer)
			return sendFn(resBuffer.Buf[:resBuffer.Position()])
		}
	}

	// Standardize name for lookup
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}
	cacheKey := fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.QType)

	// L1/L2 Check — acquire per-key lock only for atomic check-and-populate.
	// Lock is NOT held during L3 resolution to avoid serializing concurrent requests
	// that map to the same shard but have different cache keys.
	lock := globalCacheLocks.lockKey(cacheKey)
	lock.Lock()

	var cachedData []byte
	var fromL2 bool

	if cachedData, found := s.Cache.Get(cacheKey); found {
		metrics.CacheOperations.WithLabelValues("l1", "hit").Inc()
		metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
		metrics.QueryDuration.WithLabelValues("cache_l1").Observe(time.Since(start).Seconds())
		if len(cachedData) >= 2 {
			cachedData[0] = byte(request.Header.ID >> 8)
			cachedData[1] = byte(request.Header.ID & 0xFF)
		}
		lock.Unlock()
		return sendFn(cachedData)
	}
	metrics.CacheOperations.WithLabelValues("l1", "miss").Inc()

	if s.Redis != nil {
		if data, remainingTTL, found := s.Redis.GetWithTTL(ctx, cacheKey); found {
			metrics.CacheOperations.WithLabelValues("l2", "hit").Inc()
			metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
			metrics.QueryDuration.WithLabelValues("cache_l2").Observe(time.Since(start).Seconds())
			// Rewrite Transaction ID (data is a copy from Redis, safe to mutate)
			if len(data) >= 2 {
				data[0] = byte(request.Header.ID >> 8)
				data[1] = byte(request.Header.ID & 0xFF)
			}
			if remainingTTL <= 0 {
				remainingTTL = 60 * time.Second
			} else if remainingTTL > 60*time.Second {
				remainingTTL = 60 * time.Second
			}
			s.Cache.Set(cacheKey, data, remainingTTL)
			cachedData = data
			fromL2 = true
		}
	}

	lock.Unlock()

	if fromL2 {
		return sendFn(cachedData)
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
	nsidRequested := false
	var clientCookie []byte
	paddingRequested := false

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

			// Check options
			for _, opt := range res.Options {
				switch opt.Code {
				case packet.EdnsOptionNSID:
					nsidRequested = true
				case packet.EdnsOptionCookie:
					clientCookie = opt.Data
				case packet.EdnsOptionPadding:
					paddingRequested = true
				}
			}
			break
		}
	}

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Header.RecursionAvailable = s.RecursionEnabled
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
		if nsidRequested {
			opt.SetOption(packet.EdnsOptionNSID, []byte(s.NodeID))
		}
		if len(clientCookie) >= 8 {
			serverCookie := s.generateServerCookie(clientCookie[:8], clientIP)
			fullCookie := append(clientCookie[:8], serverCookie...)
			opt.SetOption(packet.EdnsOptionCookie, fullCookie)
		}
		response.Resources = append(response.Resources, opt)
	}
	source := "local"

	// Guard against nil repository (useful for identity-only nodes or tests)
	if s.Repo == nil {
		response.Header.ResCode = packet.RcodeServFail
		metrics.QueriesTotal.WithLabelValues(qTypeLabel, "2", protocol).Inc()
		resBuffer := packet.GetBuffer()
		defer packet.PutBuffer(resBuffer)
		_ = response.Write(resBuffer)
		return sendFn(resBuffer.Buf[:resBuffer.Position()])
	}

	// 1. Find the zone for this query to include Authority/Additional records
	// Use single-query longest-match instead of N+1 label traversal
	zone, _ := s.Repo.GetZoneLongestMatch(ctx, q.Name)

	// 2. Resolve Main Records
	dbStart := time.Now()
	qTypeStr := queryTypeToRecordType(q.QType)
	records, errRepo := s.Repo.GetRecords(ctx, q.Name, qTypeStr, clientIP)
	metrics.QueryDuration.WithLabelValues("database").Observe(time.Since(dbStart).Seconds())

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
				// DNSSEC: If DO bit is set and wildcard matched, include NSEC3 proof
				// Per RFC 5155 Section 7.2.14, prove the wildcard existed
				if dnssecOK && len(response.Answers) > 0 {
					nsec3params, _ := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
					if len(nsec3params) > 0 {
						nsec3, errNsec := s.generateNSEC3(ctx, zone, q.Name, wildcardName)
						if errNsec == nil {
							response.Authorities = append(response.Authorities, nsec3)
						}
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
					nsec3, errNsec := s.generateNSEC3(ctx, zone, q.Name, "")
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
			// Not authoritative for this zone - try recursive resolution if enabled
			if s.RecursionEnabled && request.Header.RecursionDesired {
				s.Logger.Info("fallback to recursive resolution", "name", q.Name, "type", q.QType)
				recursiveResp, errRecurse := s.resolveRecursive(q.Name, q.QType)
				if errRecurse == nil && recursiveResp != nil {
					response.Header.AuthoritativeAnswer = false
					response.Header.ResCode = recursiveResp.Header.ResCode
					response.Answers = recursiveResp.Answers
					response.Authorities = recursiveResp.Authorities
					// Internal recursion doesn't set recursion available in the response usually,
					// but our upstream root hints might. We already set RA in the header earlier.
				} else {
					s.Logger.Error("recursive resolution failed", "name", q.Name, "error", errRecurse)
					response.Header.AuthoritativeAnswer = false
					response.Header.ResCode = 2 // SERVFAIL
				}
			} else {
				response.Header.AuthoritativeAnswer = false
				response.Header.ResCode = 3 // NXDOMAIN
			}
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

	// DNSSEC validation (if validator is configured)
	if zone != nil {
		if err := s.validateDNSSEC(ctx, zone.Name, response); err != nil {
			// Validation failed in strict mode - convert to SERVFAIL
			if s.DNSSECMode == "strict" {
				response.Header.ResCode = packet.RcodeServFail
				response.Answers = nil
				response.Authorities = nil
			}
		}
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

	// RFC 7830 / 8467: Padding
	if paddingRequested || protocol == "dot" || protocol == "doh" {
		blockSize := 128
		if response.Header.Response {
			blockSize = 468 // Recommended response block size
		}
		s.padResponse(response, blockSize)
	}

	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	resBuffer.HasNames = true // Enable Name Compression
	_ = response.Write(resBuffer)

	if resBuffer.Position() > maxSize {
		response.Header.TruncatedMessage = true
		response.Answers = nil
		response.Authorities = nil
		// RFC 6891: Preserve OPT records (type 41) when truncating
		var optRecords []packet.DNSRecord
		for _, res := range response.Resources {
			if res.Type == packet.OPT {
				optRecords = append(optRecords, res)
			}
		}
		response.Resources = optRecords
		resBuffer.Reset()
		resBuffer.HasNames = true
		_ = response.Write(resBuffer)
		// If still too large (e.g., due to large EDNS options like padding), remove OPT entirely
		if resBuffer.Position() > maxSize {
			response.Resources = nil
			resBuffer.Reset()
			resBuffer.HasNames = true
			_ = response.Write(resBuffer)
		}
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

	metrics.QueriesTotal.WithLabelValues(qTypeLabel, fmt.Sprintf("%d", response.Header.ResCode), protocol).Inc()
	s.Logger.Info("query processed", "name", q.Name, "src", source, "lat", time.Since(start).Milliseconds())
	return sendFn(resData)
}

func (s *Server) handleNotify(ctx context.Context, request *packet.DNSPacket, clientIP string, sendFn func([]byte) error) error {
	if len(request.Questions) == 0 {
		s.Logger.Warn("received NOTIFY without questions", "from", clientIP)
		return nil
	}
	s.Logger.Info("received NOTIFY", "zone", request.Questions[0].Name, "from", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeNotify
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, request.Questions[0])

	// Trigger async refresh if it's a slave zone
	if !s.DisableAsync {
		go func(zoneName string) {
			select {
			case <-ctx.Done():
				return
			case <-s.done:
				return
			default:
			}
			zone, err := s.Repo.GetZone(ctx, zoneName)
			if err != nil {
				s.Logger.Error("failed to fetch zone for notify refresh", "zone", zoneName, "error", err)
				return
			}
			if zone != nil && zone.Role == "slave" {
				s.refreshZone(ctx, zone)
			}
		}(request.Questions[0].Name)
	}

	response.Header.ResCode = packet.RcodeNoError
	return s.sendUpdateResponse(response, sendFn)
}

func (s *Server) handleUpdate(ctx context.Context, request *packet.DNSPacket, rawData []byte, clientIP string, sendFn func([]byte) error) error {
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

	// 3. Prepare Updates (UPCOUNT)
	operations := make([]domain.UpdateOperation, 0, len(request.Authorities))
	changes := make([]domain.ZoneChange, 0, len(request.Authorities))

	for _, up := range request.Authorities {
		op, change, errPrep := s.prepareUpdate(dbZone.ID, up)
		if errPrep != nil {
			s.Logger.Error("update failed: conversion error", "error", errPrep)
			response.Header.ResCode = packet.RcodeServFail
			return s.sendUpdateResponse(response, sendFn)
		}
		operations = append(operations, op)
		changes = append(changes, change)
	}

	// 4. Handle Serial Increment and Atomic Apply
	if len(changes) > 0 {
		// Apply everything in a single transaction
		// Repository fetches current SOA serial inside the tx and increments atomically
		newSerial, errApply := s.Repo.ApplyZoneUpdate(ctx, dbZone.ID, operations, changes)
		if errApply != nil {
			s.Logger.Error("atomic update failed", "zone", dbZone.Name, "error", errApply)
			response.Header.ResCode = packet.RcodeServFail
			return s.sendUpdateResponse(response, sendFn)
		}

		if newSerial > 0 {
			s.Logger.Info("dynamic update successful", "zone", zone.Name, "new_serial", newSerial)
		} else {
			s.Logger.Info("dynamic update applied without serial increment (no SOA found)", "zone", zone.Name)
		}

		s.Cache.Flush()
		if s.Redis != nil {
			_ = s.Redis.Invalidate(ctx, zone.Name, "")
		}
		if !s.DisableAsync {
			go s.notifySlaves(ctx, zone.Name)
		}
		response.Header.ResCode = packet.RcodeNoError
		return s.sendUpdateResponse(response, sendFn)
	}

	// 5. Success (no changes)
	response.Header.ResCode = packet.RcodeNoError
	s.Logger.Info("dynamic update processed", "zone", zone.Name)
	s.Cache.Flush()
	if s.Redis != nil {
		_ = s.Redis.Invalidate(ctx, zone.Name, "")
	}

	if !s.DisableAsync {
		go s.notifySlaves(ctx, zone.Name)
	}

	return s.sendUpdateResponse(response, sendFn)
}

func (s *Server) handleIXFR(ctx context.Context, conn net.Conn, request *packet.DNSPacket, rawData []byte) {
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Validate TSIG if present
	if request.TSIGStart != -1 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Warn("IXFR failed: unknown TSIG key", "key", tsig.Name, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, secret); errVerify != nil {
			s.Logger.Warn("IXFR failed: TSIG verification failed", "error", errVerify, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	// RFC 1995: The client's current SOA is in the Authority section
	if len(request.Authorities) == 0 || request.Authorities[0].Type != packet.SOA {
		s.Logger.Warn("IXFR requested without client SOA in Authority section", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 1) // FORMERR
		return
	}
	clientSOA := request.Authorities[0]
	clientSerial := clientSOA.Serial

	zone, err := s.Repo.GetZone(ctx, q.Name)
	if err != nil || zone == nil {
		s.Logger.Warn("IXFR requested for non-existent zone", "name", q.Name, "error", err)
		s.sendTCPError(conn, request.Header.ID, 3) // NXDOMAIN
		return
	}

	// Get current SOA
	soaRecords, err := s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, "")
	if err != nil || len(soaRecords) == 0 {
		s.Logger.Error("IXFR failed: zone has no SOA", "zone", zone.Name, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}
	currentSOA := soaRecords[0]
	fields := strings.Fields(currentSOA.Content)
	if len(fields) < 3 {
		s.Logger.Error("IXFR failed: malformed SOA content", "zone", zone.Name, "content", currentSOA.Content)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	var currentSerial uint32
	if _, err := fmt.Sscanf(fields[2], "%d", &currentSerial); err != nil {
		s.Logger.Error("IXFR failed: invalid SOA serial", "zone", zone.Name, "serial", fields[2], "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	if clientSerial == currentSerial {
		// Client is up to date, just send current SOA
		s.Logger.Info("IXFR client is up to date", "zone", zone.Name, "serial", clientSerial)
		pSOA, err := repository.ConvertDomainToPacketRecord(currentSOA)
		if err == nil {
			s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)
		}
		return
	}

	// Fetch changes since clientSerial using IXFR chain logic
	chunks, err := s.Repo.GetIXFRChain(ctx, zone.ID, clientSerial, currentSerial)

	// RFC 1995: Verify full IXFR chain continuity
	// Note: clientSerial+1 wraps to 0 when clientSerial is max uint32.
	// In that case, we can only validate if chunks starts at 0 (which is valid after wrap).
	historyValid := false
	if len(chunks) > 0 {
		if clientSerial == math.MaxUint32 {
			// Overflow case: client is at max uint32, first chunk must be at 0
			// Sequential check below will validate the chain
			historyValid = chunks[0].Serial == 0
		} else {
			historyValid = chunks[0].Serial == clientSerial+1
		}
	}
	if historyValid {
		for i := 1; i < len(chunks); i++ {
			// Use uint32 wrap-around aware comparison for sequential serials
			expectedSerial := chunks[i-1].Serial + 1
			if chunks[i].Serial != expectedSerial {
				historyValid = false
				break
			}
		}
	}
	// Verify the last chunk reaches currentSerial (rejects truncated chains)
	if historyValid && len(chunks) > 0 {
		if chunks[len(chunks)-1].Serial != currentSerial {
			historyValid = false
		}
	}

	if err != nil {
		s.Logger.Warn("IXFR chain query failed, falling back to AXFR", "zone", zone.Name, "error", err)
	} else if !historyValid {
		s.Logger.Info("IXFR history gap detected, falling back to AXFR",
			"zone", zone.Name, "client_serial", clientSerial)

		// RFC 1995: If IXFR is not possible, fall back to AXFR sequence using streaming
		iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
		if errIter != nil {
			s.Logger.Error("IXFR/AXFR fallback failed to open record stream", "zone", zone.Name, "error", errIter)
			s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
			return
		}
		defer func() { _ = iter.Close() }()

		pSOA, errConv := repository.ConvertDomainToPacketRecord(currentSOA)
		if errConv != nil {
			s.Logger.Error("IXFR/AXFR fallback failed to convert SOA", "zone", zone.Name, "error", errConv)
			s.sendTCPError(conn, request.Header.ID, 2)
			return
		}

		// 2. Send Current SOA (start)
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)

		// 3. Stream all records in the zone
		for iter.Next() {
			rec := iter.Record()
			if rec.Type == domain.TypeSOA {
				continue
			}
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				s.sendSingleRecordResponse(conn, request.Header.ID, q, pRec)
			}
		}
		if err := iter.Err(); err != nil {
			s.Logger.Error("IXFR/AXFR fallback failed during streaming", "zone", zone.Name, "error", err)
			s.sendTCPError(conn, request.Header.ID, 2)
			return
		}

		// 4. Send Current SOA (end)
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)
		return
	}

	s.Logger.Info("IXFR starting", "zone", zone.Name, "from", clientSerial, "to", currentSerial, "chunks", len(chunks))

	// Send Current SOA (marks start of IXFR)
	pCurrentSOA, err := repository.ConvertDomainToPacketRecord(currentSOA)
	if err == nil {
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pCurrentSOA)
	}

	// Send each chunk
	for _, chunk := range chunks {
		// RFC 1995: IXFR sequence is [SOA(new), (SOA(old), deleted..., SOA(new), added...)*, SOA(new)]
		// Note: The outer handleIXFR sends the first and last SOA(new).

		// 1. Send Old SOA (from deletions if available to preserve fields)
		var oldSOA domain.Record
		foundOld := false
		for _, r := range chunk.Deleted {
			if r.Type == domain.TypeSOA {
				oldSOA = r
				foundOld = true
				break
			}
		}
		if !foundOld {
			oldSOA = currentSOA
			// We don't have the original old SOA in the chunk, fallback to current but with old serial
			// (This shouldn't happen with our bounded delta logger)
			parts := strings.Fields(oldSOA.Content)
			if len(parts) >= 3 {
				parts[2] = fmt.Sprintf("%d", clientSerial)
				oldSOA.Content = strings.Join(parts, " ")
			}
		}
		pOldSOA, err := repository.ConvertDomainToPacketRecord(oldSOA)
		if err == nil {
			s.sendSingleRecordResponse(conn, request.Header.ID, q, pOldSOA)
		}

		// 2. Send Deletions
		for _, rec := range chunk.Deleted {
			if rec.Type == domain.TypeSOA {
				continue
			}
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				s.sendSingleRecordResponse(conn, request.Header.ID, q, pRec)
			}
		}

		// 3. Send New SOA (from additions)
		var newSOA domain.Record
		foundNew := false
		for _, r := range chunk.Added {
			if r.Type == domain.TypeSOA {
				newSOA = r
				foundNew = true
				break
			}
		}
		if !foundNew {
			newSOA = currentSOA
			parts := strings.Fields(newSOA.Content)
			if len(parts) >= 3 {
				parts[2] = fmt.Sprintf("%d", chunk.Serial)
				newSOA.Content = strings.Join(parts, " ")
			}
		}
		pNewSOA, err := repository.ConvertDomainToPacketRecord(newSOA)
		if err == nil {
			s.sendSingleRecordResponse(conn, request.Header.ID, q, pNewSOA)
		}

		// 4. Send Additions
		for _, rec := range chunk.Added {
			if rec.Type == domain.TypeSOA {
				continue
			}
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				s.sendSingleRecordResponse(conn, request.Header.ID, q, pRec)
			}
		}

		// For the next chunk, clientSerial is now this chunk's Serial
		clientSerial = chunk.Serial
	}

	// Send Current SOA (marks end of IXFR)
	if err == nil {
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pCurrentSOA)
	}
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

// validateDNSSEC validates DNSSEC signatures on a response.
// It checks the AD bit based on validation result and dnssecMode.
// Returns an error if validation failed (in strict mode) or if DNSKEYs could not be fetched.
func (s *Server) validateDNSSEC(ctx context.Context, zoneName string, response *packet.DNSPacket) error {
	if s.DNSSECValidator == nil || s.DNSSECMode == "disabled" {
		return nil
	}

	// Collect all RRSIGs from the response, grouped by covered rrset
	// Key: "name:typeCovered" -> value: []packet.DNSRecord of RRSIGs
	rrsigGroups := make(map[string][]packet.DNSRecord)
	for _, rec := range response.Answers {
		if rec.Type == packet.RRSIG {
			key := fmt.Sprintf("%s:%d", strings.ToLower(rec.Name), rec.TypeCovered)
			rrsigGroups[key] = append(rrsigGroups[key], rec)
		}
	}
	for _, rec := range response.Authorities {
		if rec.Type == packet.RRSIG {
			key := fmt.Sprintf("%s:%d", strings.ToLower(rec.Name), rec.TypeCovered)
			rrsigGroups[key] = append(rrsigGroups[key], rec)
		}
	}

	if len(rrsigGroups) == 0 {
		return nil // No signatures to validate
	}

	// Fetch DNSKEYs for validation
	dnskeyRecords, err := s.Repo.GetDNSKEYs(ctx, zoneName)
	if err != nil {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: failed to fetch dnskeys: %w", err)
		}
		return nil
	}

	// If no DNSKEYs from repo, try fetching from network
	if len(dnskeyRecords) == 0 && s.RecursionEnabled {
		netDNSKEYs, netErr := s.fetchDNSKEYFromNetwork(ctx, zoneName)
		if netErr == nil {
			// Convert network DNSKEYs to domain records
			for _, dk := range netDNSKEYs {
				if domRec, err := repository.ConvertPacketRecordToDomain(dk, ""); err == nil {
					dnskeyRecords = append(dnskeyRecords, domRec)
				}
			}
		}
	}

	if len(dnskeyRecords) == 0 {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: no dnskeys available for validation")
		}
		return nil
	}

	// Convert domain records to packet records for validation
	var dnskeys []packet.DNSRecord
	for _, rec := range dnskeyRecords {
		pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
		if errConv != nil {
			continue
		}
		if pRec.Type != packet.DNSKEY {
			continue
		}
		if pRec.Type == packet.DNSKEY && len(pRec.PublicKey) > 0 {
			dnskeys = append(dnskeys, pRec)
		}
	}

	if len(dnskeys) == 0 {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: no valid dnskeys found")
		}
		return nil
	}

	// Get current time for validation.
	now := utils.GetCurrentTimeUint32()

	// Validate each unique RRset with its matching RRSIGs
	allValid := true
	for key, sigs := range rrsigGroups {
		// Parse key to get name and type
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			continue
		}
		rrsigName := parts[0]
		coveredType := packet.QueryType(0)
		if _, err := fmt.Sscanf(parts[1], "%d", &coveredType); err != nil {
			continue
		}

		// Build the RRset from response.Answers and response.Authorities
		var rrset []packet.DNSRecord
		for _, ans := range response.Answers {
			if ans.Type == coveredType && strings.ToLower(ans.Name) == rrsigName {
				rrset = append(rrset, ans)
			}
		}
		for _, auth := range response.Authorities {
			if auth.Type == coveredType && strings.ToLower(auth.Name) == rrsigName {
				rrset = append(rrset, auth)
			}
		}

		if len(rrset) == 0 {
			continue // No matching rrset for this group of RRSIGs
		}

		result := s.DNSSECValidator.ValidateRRSet(rrset, sigs, dnskeys, now)
		if !result.Valid {
			allValid = false
			if s.DNSSECMode == "strict" {
				return fmt.Errorf("dnssec: validation failed for %s: %v", rrsigName, result.EDE)
			}
		}
	}

	response.Header.AuthedData = allValid
	return nil
}

// fetchDNSKEYFromNetwork queries DNSKEY records for a zone from the network.
// It returns the DNSKEY records and an error if the query failed.
func (s *Server) fetchDNSKEYFromNetwork(_ context.Context, zoneName string) ([]packet.DNSRecord, error) {
	// First try to resolve DNSKEY via recursive resolution
	dnskeyResp, err := s.resolveRecursive(zoneName, packet.DNSKEY)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNSKEY for %s: %w", zoneName, err)
	}

	var dnskeys []packet.DNSRecord
	// Collect DNSKEY records from answers
	for _, rec := range dnskeyResp.Answers {
		if rec.Type == packet.DNSKEY && len(rec.PublicKey) > 0 {
			dnskeys = append(dnskeys, rec)
		}
	}
	// Also check authorities (some servers put DNSKEYs there)
	for _, rec := range dnskeyResp.Authorities {
		if rec.Type == packet.DNSKEY && len(rec.PublicKey) > 0 {
			dnskeys = append(dnskeys, rec)
		}
	}

	if len(dnskeys) == 0 {
		return nil, fmt.Errorf("no DNSKEY records found for %s", zoneName)
	}
	return dnskeys, nil
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
	// TCP requires 2-byte length prefix
	fullLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(fullLen >> 8), byte(fullLen & 0xFF)}, resData...)
	_, _ = conn.Write(fullResp)
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
// prepareUpdate converts a DNS record update from an RFC 2136 message into an internal
// atomic operation and its corresponding historical change record.
func (s *Server) prepareUpdate(zoneID string, up packet.DNSRecord) (domain.UpdateOperation, domain.ZoneChange, error) {
	upName := up.Name
	if !strings.HasSuffix(upName, ".") {
		upName += "."
	}

	op := domain.UpdateOperation{}
	dRec, errConv := repository.ConvertPacketRecordToDomain(up, zoneID)
	if errConv != nil && up.Class != 255 { // Class ANY might fail conversion if RDATA is missing
		return op, domain.ZoneChange{}, errConv
	}

	switch up.Class {
	case 255: // ANY: Delete RRset (RFC 2136 Section 2.5.2)
		if up.Type == 255 {
			op.Action = domain.ActionDeleteAll
		} else {
			op.Action = domain.ActionDeleteRRSet
		}
		op.Record = domain.Record{
			ZoneID: zoneID,
			Name:   upName,
			Type:   domain.RecordType(up.Type.String()),
		}
	case 254: // NONE: Delete specific record (RFC 2136 Section 2.5.4)
		op.Action = domain.ActionDeleteSpecific
		op.Record = dRec
	default: // Add record (RFC 2136 Section 2.5.1)
		op.Action = domain.ActionAdd
		if dRec.ID == "" {
			var bid [16]byte
			_, _ = crand.Read(bid[:])
			dRec.ID = fmt.Sprintf("%d-%x", time.Now().UnixNano(), bid)
		}
		if dRec.CreatedAt.IsZero() {
			dRec.CreatedAt = time.Now()
			dRec.UpdatedAt = time.Now()
		}
		op.Record = dRec
	}

	// Prepare historical change record for IXFR
	var rb [8]byte
	_, _ = crand.Read(rb[:])
	randomPart := binary.LittleEndian.Uint64(rb[:])
	change := domain.ZoneChange{
		ID:        fmt.Sprintf("%d-%x", time.Now().UnixNano(), randomPart),
		ZoneID:    zoneID,
		Name:      upName,
		Type:      domain.RecordType(up.Type.String()),
		TTL:       int(up.TTL),
		CreatedAt: time.Now(),
	}
	if op.Action == domain.ActionAdd {
		change.Action = "ADD"
		change.Content = op.Record.Content
		change.Priority = op.Record.Priority
	} else {
		change.Action = "DELETE"
		if op.Action == domain.ActionDeleteSpecific {
			change.Content = op.Record.Content
		}
	}

	return op, change, nil
}

func (s *Server) notifySlaves(ctx context.Context, zoneName string) {
	select {
	case <-ctx.Done():
		return
	case <-s.done:
		return
	default:
	}
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
	iter, errZoneRecs := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
	if errZoneRecs != nil {
		return packet.DNSRecord{}, errZoneRecs
	}
	defer func() { _ = iter.Close() }()

	nameToTypes := make(map[string][]domain.RecordType)
	var uniqueNames []string
	seen := make(map[string]bool)
	for iter.Next() {
		r := iter.Record()
		if !seen[r.Name] {
			uniqueNames = append(uniqueNames, r.Name)
			seen[r.Name] = true
		}
		nameToTypes[r.Name] = append(nameToTypes[r.Name], r.Type)
	}
	if err := iter.Err(); err != nil {
		return packet.DNSRecord{}, err
	}

	if len(uniqueNames) == 0 {
		return packet.DNSRecord{}, fmt.Errorf("no records in zone")
	}

	sort.Slice(uniqueNames, func(i, j int) bool {
		return master.CompareNamesCanonically(uniqueNames[i], uniqueNames[j]) < 0
	})

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

func (s *Server) generateNSEC3(ctx context.Context, zone *domain.Zone, queryName string, wildcardName string) (packet.DNSRecord, error) {
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

	iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
	if errIter != nil {
		return packet.DNSRecord{}, errIter
	}
	defer func() { _ = iter.Close() }()

	nameToTypes := make(map[string][]domain.RecordType)
	var ownerNames []string
	seen := make(map[string]bool)
	for iter.Next() {
		r := iter.Record()
		if !seen[r.Name] {
			ownerNames = append(ownerNames, r.Name)
			seen[r.Name] = true
		}
		nameToTypes[r.Name] = append(nameToTypes[r.Name], r.Type)
	}
	_ = iter.Err()

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

	// If wildcardName is provided, generate NSEC3 for wildcard proof
	if wildcardName != "" {
		return s.generateNSEC3ForWildcardProof(ctx, zone, wildcardName, queryName, alg, iterations, salt, hashes, nameToTypes)
	}

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

// generateNSEC3ForWildcardProof generates an NSEC3 record proving a wildcard match.
// Per RFC 5155 Section 7.2.14, the NSEC3 proves that the wildcard RRset exists.
func (s *Server) generateNSEC3ForWildcardProof(_ context.Context, zone *domain.Zone, wildcardName, _ string, alg uint8, iterations uint16, salt string, hashes []hashEntry, nameToTypes map[string][]domain.RecordType) (packet.DNSRecord, error) {
	// Hash the wildcard name
	wildcardHash := packet.HashName(wildcardName, alg, iterations, []byte(salt))

	// Find the wildcard hash in the chain and get next hash
	var nextEntry hashEntry
	wildcardIdx := -1
	for i, h := range hashes {
		if bytes.Equal(h.hash, wildcardHash) {
			wildcardIdx = i
			break
		}
	}

	if wildcardIdx == -1 {
		return packet.DNSRecord{}, fmt.Errorf("wildcard hash not found in NSEC3 chain")
	}

	// Next hash in the chain
	if wildcardIdx == len(hashes)-1 {
		nextEntry = hashes[0]
	} else {
		nextEntry = hashes[wildcardIdx+1]
	}

	// Get types from wildcard record and add the query type
	types := nameToTypes[wildcardName]
	types = append(types, "NSEC3")
	bitmap := s.generateTypeBitMap(types)

	nsec3 := packet.DNSRecord{
		Name:       packet.Base32Encode(wildcardHash) + "." + zone.Name,
		Type:       packet.NSEC3,
		Class:      1,
		TTL:        300,
		HashAlg:    alg,
		Flags:      0,
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

	res := make([]byte, 0, 2+(maxType+1))
	res = append(res, 0, byte(maxType+1))
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
	case packet.SRV:
		return domain.TypeSRV
	case packet.PTR:
		return domain.TypePTR
	case packet.CAA:
		return domain.TypeCAA
	case packet.HTTPS:
		return domain.TypeHTTPS
	case packet.DS:
		return domain.RecordType("DS")
	case packet.DNSKEY:
		return domain.RecordType("DNSKEY")
	case packet.RRSIG:
		return domain.RecordType("RRSIG")
	case packet.NSEC:
		return domain.RecordType("NSEC")
	case packet.NSEC3:
		return domain.RecordType("NSEC3")
	case packet.ANY:
		return ""
	default:
		return ""
	}
}
