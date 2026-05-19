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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

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

// fnv32 returns a 32-bit FNV-1a hash of the key for cache lock sharding.
func fnv32(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key)) // #nosec G104
	return h.Sum32()
}

// lockKey returns the cache lock shard for the given key using FNV hashing.
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

	// inflightCache prevents thundering herd: tracks keys currently being fetched from L2.
	// Key -> *inflightEntry (done channel closed when fetch completes).
	inflightCache sync.Map
}

// inflightEntry holds state for an in-progress L2 cache fetch.
// The done channel is closed by the fetching goroutine when it finishes,
// unblocking all goroutines that were waiting on it.
type inflightEntry struct {
	done chan struct{}
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

// generateServerCookie creates a DNS COOKIE (RFC 9013) server cookie from a client cookie and client IP.
func (s *Server) generateServerCookie(clientCookie []byte, clientIP string) []byte {
	h := hmac.New(sha256.New, s.CookieSecret)
	h.Write(clientCookie)
	h.Write([]byte(clientIP))
	return h.Sum(nil)[:16] // Return 16 bytes of server cookie
}

// padResponse pads a DNS response to a multiple of blockSize for privacy (RFC 9276).
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

// automateDNSSEC runs periodic DNSSEC key lifecycle management for all zones.
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

	// Update DNSSEC key metrics after automation
	s.updateDNSSECMetrics(ctx)
}

func (s *Server) updateDNSSECMetrics(ctx context.Context) {
	if s.DNSSEC == nil {
		return
	}
	stats, err := s.DNSSEC.CollectKeyStats(ctx)
	if err != nil {
		s.Logger.Debug("failed to collect DNSSEC key stats", "error", err)
		return
	}
	metrics.DNSSECKeysTotal.Reset()
	metrics.DNSSECKeysAgeSeconds.Reset()
	signedZones := 0
	for _, st := range stats {
		metrics.DNSSECKeysTotal.WithLabelValues(st.ZoneName, st.KeyType, fmt.Sprintf("%d", st.Algorithm)).Set(1)
		metrics.DNSSECKeysAgeSeconds.WithLabelValues(st.ZoneName, st.KeyType).Set(st.AgeSeconds)
		signedZones++
	}
	metrics.DNSSECZonesSigned.Set(float64(signedZones))
}

// startInvalidationListener listens for cache invalidation events from Redis pub/sub.
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
			// msg.Payload format is "name:type" for record-level, or just "name" for zone-level
			s.Logger.Debug("received cache invalidation event", "key", msg.Payload)

			// Zone-level invalidation: flush entire L1 cache
			if !strings.Contains(msg.Payload, ":") {
				s.Logger.Debug("zone-level cache invalidation, flushing L1", "zone", msg.Payload)
				s.Cache.Flush()
				continue
			}

			// Record-level invalidation
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

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.Logger.Info("stopping DLQ retry worker")
			return
		case <-ticker.C:
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
			if err := s.tcpListener.Close(); err != nil {
				s.Logger.Warn("failed to close TCP listener", "error", err)
			}
		}
		if s.dotListener != nil {
			if err := s.dotListener.Close(); err != nil {
				s.Logger.Warn("failed to close DoT listener", "error", err)
			}
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
		defer shutdownCancel()
		if s.dohServer != nil {
			if err := s.dohServer.Shutdown(shutdownCtx); err != nil {
				s.Logger.Warn("failed to shut down DoH server", "error", err)
			}
		}
		if s.doqListener != nil {
			if err := s.doqListener.Close(); err != nil {
				s.Logger.Warn("failed to close DoQ listener", "error", err)
			}
		}
		if s.Redis != nil {
			errCh := make(chan error, 1)
			go func() { errCh <- s.Redis.Close() }()
			select {
			case err := <-errCh:
				if err != nil {
					s.Logger.Error("redis shutdown failed", "error", err)
				}
			case <-shutdownCtx.Done():
				s.Logger.Warn("redis close timed out during shutdown")
			}
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
				if err := c.Close(); err != nil {
					s.Logger.Warn("failed to close UDP listener", "error", err)
				}
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
					// Copy buffer since the backing array is reused across ReadFrom calls.
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
				if err := s.tcpListener.Close(); err != nil {
					s.Logger.Warn("failed to close TCP listener", "error", err)
				}
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
					if err := s.dotListener.Close(); err != nil {
						s.Logger.Warn("failed to close DoT listener", "error", err)
					}
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

// handleDoH handles DNS-over-HTTPS requests (RFC 8484).
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

// udpWorker processes UDP DNS tasks from the server's task queue.
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

// handleUDPConnection processes a single UDP DNS packet and sends the response back.
func (s *Server) handleUDPConnection(ctx context.Context, pc net.PacketConn, addr net.Addr, data []byte) {
	if errHandle := s.handlePacket(ctx, data, addr, func(resp []byte) error {
		_, errWrite := pc.WriteTo(resp, addr)
		return errWrite
	}, "udp"); errHandle != nil {
		s.Logger.Error("failed to handle UDP packet", "error", errHandle)
	}
}

// handleTCPConnection reads DNS messages from a TCP connection until the connection closes.
func (s *Server) handleTCPConnection(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		lenBuf := [2]byte{}
		if _, errRead := io.ReadFull(conn, lenBuf[:]); errRead != nil {
			return
		}
		packetLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
		reqBuffer := packet.GetBuffer()
		if _, errRead := io.ReadFull(conn, reqBuffer.Buf[:packetLen]); errRead != nil {
			packet.PutBuffer(reqBuffer)
			return
		}
		reqBuffer.Load(reqBuffer.Buf[:packetLen]) // initializes Pos, Len, parsing, names — copy is a no-op since data is already in Buf

		request := packet.NewDNSPacket()
		if errFromBuf := request.FromBuffer(reqBuffer); errFromBuf == nil && len(request.Questions) > 0 {
			if request.Questions[0].QType == packet.AXFR {
				s.handleAXFR(ctx, conn, request, reqBuffer.Buf[:packetLen], reqBuffer)
				continue
			}
			if request.Questions[0].QType == packet.IXFR {
				s.handleIXFR(ctx, conn, request, reqBuffer.Buf[:packetLen], reqBuffer)
				continue
			}
		}
		packet.PutBuffer(reqBuffer)

		if errHandle := s.handlePacket(ctx, reqBuffer.Buf[:packetLen], conn.RemoteAddr(), func(resp []byte) error {
			resLen := uint16(len(resp)) // #nosec G115
			fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resp...)
			_, errWrite := conn.Write(fullResp)
			return errWrite
		}, "tcp"); errHandle != nil {
			s.Logger.Error("Failed to handle TCP packet", "error", errHandle)
		}
	}
}

// handleAXFR processes a DNS zone transfer (AXFR) request over TCP.
func (s *Server) handleAXFR(ctx context.Context, conn net.Conn, request *packet.DNSPacket, rawData []byte, buffer *packet.BytePacketBuffer) {
	defer packet.PutBuffer(buffer)
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Validate TSIG if present
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Debug("AXFR failed: unknown TSIG key", "key", tsig.Name, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, secret); errVerify != nil {
			s.Logger.Warn("AXFR failed: TSIG verification failed", "error", errVerify, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	zone, err := s.Repo.GetZone(ctx, q.Name)
	if err != nil {
		s.Logger.Error("AXFR failed to look up zone", "zone", q.Name, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
		return
	}
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
	metrics.AXFRBytesTotal.Add(float64(len(fullResp)))
}

// sendTCPError sends a TCP DNS error response with the given RCODE.
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

// handlePacket parses and dispatches a DNS packet to the appropriate handler.
func (s *Server) handlePacket(ctx context.Context, data []byte, srcAddr interface{}, sendFn func([]byte) error, protocol string) error {
	start := time.Now()
	defer func() {
		metrics.QueryDuration.WithLabelValues("total").Observe(time.Since(start).Seconds())
	}()

	clientIP := extractClientIP(srcAddr)
	if !s.limiter.Allow(clientIP) {
		return nil
	}

	request, errParse := s.parsePacket(data)
	if errParse != nil {
		s.Logger.Error("failed to parse packet", "error", errParse)
		return errParse
	}

	qTypeLabel := "UNKNOWN"
	if len(request.Questions) > 0 {
		qTypeLabel = request.Questions[0].QType.String()
	}

	// Opcode routing
	switch request.Header.Opcode {
	case packet.OpcodeUpdate:
		err := s.handleUpdate(ctx, request, data, clientIP, sendFn)
		metrics.QueriesTotal.WithLabelValues("UPDATE", rcodeLabel(err, request), protocol).Inc()
		return err
	case packet.OpcodeNotify:
		err := s.handleNotify(ctx, request, clientIP, sendFn)
		metrics.QueriesTotal.WithLabelValues("NOTIFY", "0", protocol).Inc()
		return err
	}

	// Empty questions → FORMERR
	if len(request.Questions) == 0 {
		return s.sendFORMERR(request, sendFn, qTypeLabel, protocol)
	}

	q := request.Questions[0]

	// CHAOS identity queries
	if q.QClass == ClassCHAOS {
		if strings.ToLower(q.Name) == "id.server." || strings.ToLower(q.Name) == "hostname.bind." {
			return s.sendCHAOSIdentity(request, q, sendFn, qTypeLabel, protocol)
		}
	}

	// Standardize name
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}
	cacheKey := fmt.Sprintf("%s:%d", strings.ToLower(q.Name), q.QType)

	// Cache check (L1 + L2)
	if cached := s.checkCache(ctx, request, cacheKey, clientIP, qTypeLabel, protocol, sendFn); cached != nil {
		return nil
	}

	// DB latency simulation
	s.simulateDBLatency()

	// EDNS0 processing
	clientOPT, maxSize, dnssecOK, nsidRequested, clientCookie, paddingRequested := s.processEDNS0(request)

	// Build response skeleton
	response := s.newResponseSkeleton(request, q, clientOPT, dnssecOK, nsidRequested, clientCookie)
	source := "local"

	// Guard against nil repository
	if s.Repo == nil {
		return s.sendServFail(response, sendFn, qTypeLabel, protocol)
	}

	// Zone lookup + record resolution — run in parallel since they query different tables
	var (
		zone    *domain.Zone
		records []domain.Record
		errRepo error
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(2)

	g.Go(func() error {
		var err error
		zone, err = s.Repo.GetZoneLongestMatch(ctx, q.Name)
		return err
	})

	g.Go(func() error {
		var err error
		records, err = s.Repo.GetRecords(ctx, q.Name, queryTypeToRecordType(q.QType), clientIP)
		errRepo = err
		return err
	})

	// errgroup returns the first non-nil error, but we intentionally allow partial
	// results since zone lookup failure should not block record lookup (and vice versa).
	// Both goroutines run to completion before Wait returns.
	_ = g.Wait()

	if errRepo == nil && len(records) > 0 {
		s.appendRecordsToResponse(response, records)
	} else if zone != nil {
		source = "wildcard"
		if recs, nsec3 := s.resolveWithWildcard(ctx, q, zone, dnssecOK, clientIP); len(recs) > 0 {
			s.appendRecordsToResponse(response, recs)
			if nsec3 != nil {
				response.Authorities = append(response.Authorities, *nsec3)
			}
		}
	}

	// Handle NXDOMAIN / NoData / authoritative
	if len(response.Answers) == 0 {
		s.handleNxDomain(ctx, request, q, zone, dnssecOK, clientOPT, clientIP, response)
	} else if zone != nil {
		s.populateAuthorityAndAdditional(ctx, response, zone, clientIP)
	}

	// DNSSEC signing
	if dnssecOK && zone != nil {
		s.signResponse(ctx, zone, response)
	}

	// DNSSEC validation
	if zone != nil {
		s.validateDNSSECResponse(ctx, zone, response)
	}

	// Re-extract maxSize from OPT for truncation
	maxSize = s.extractMaxSizeFromOPT(request, maxSize)

	// Padding
	if paddingRequested || protocol == "dot" || protocol == "doh" {
		s.padResponse(response, 468)
	}

	// Write + truncate
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	resBuffer.HasNames = true
	_ = response.Write(resBuffer)
	s.truncateIfNeeded(response, resBuffer, maxSize)
	resData := resBuffer.Buf[:resBuffer.Position()]

	// Cache result
	s.cacheResult(ctx, cacheKey, resData, response)

	metrics.QueriesTotal.WithLabelValues(qTypeLabel, fmt.Sprintf("%d", response.Header.ResCode), protocol).Inc()
	s.Logger.Info("query processed", "name", q.Name, "src", source, "lat", time.Since(start).Milliseconds())
	return sendFn(resData)
}

func rcodeLabel(err error, req *packet.DNSPacket) string {
	if err == nil {
		return fmt.Sprintf("%d", req.Header.ResCode)
	}
	return "0"
}

// extractClientIP extracts the client IP address from the source address.
func extractClientIP(srcAddr interface{}) string {
	switch addr := srcAddr.(type) {
	case string:
		ip, _, _ := net.SplitHostPort(addr)
		return ip
	case net.Addr:
		ip, _, _ := net.SplitHostPort(addr.String())
		return ip
	}
	return ""
}

// parsePacket parses a DNS packet from raw data.
func (s *Server) parsePacket(data []byte) (*packet.DNSPacket, error) {
	reqBuffer := packet.GetBuffer()
	defer packet.PutBuffer(reqBuffer)
	reqBuffer.Load(data)
	request := packet.NewDNSPacket()
	if err := request.FromBuffer(reqBuffer); err != nil {
		return nil, err
	}
	return request, nil
}

// sendFORMERR sends a FORMERR response for empty question packets.
func (s *Server) sendFORMERR(req *packet.DNSPacket, sendFn func([]byte) error, _, protocol string) error {
	response := packet.NewDNSPacket()
	response.Header.ID = req.Header.ID
	response.Header.Response = true
	response.Header.ResCode = 4 // FORMERR
	metrics.QueriesTotal.WithLabelValues("NONE", "4", protocol).Inc()
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	_ = response.Write(resBuffer)
	return sendFn(resBuffer.Buf[:resBuffer.Position()])
}

// sendCHAOSIdentity responds to CHAOS identity queries (id.server., hostname.bind.).
func (s *Server) sendCHAOSIdentity(req *packet.DNSPacket, q packet.DNSQuestion, sendFn func([]byte) error, qTypeLabel, protocol string) error {
	response := packet.NewDNSPacket()
	response.Header.ID = req.Header.ID
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, q)
	response.Answers = append(response.Answers, packet.DNSRecord{
		Name:  q.Name,
		Type:  packet.TXT,
		Class: ClassCHAOS,
		TTL:   0,
		Txt:   s.NodeID,
	})
	metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	_ = response.Write(resBuffer)
	return sendFn(resBuffer.Buf[:resBuffer.Position()])
}

// checkCache checks L1 and L2 cache, sends response directly if found.
// Returns nil if no cached data was found.
// Uses an inflight map to prevent thundering herd: if another goroutine is already
// fetching L2 for this key, we wait and use the L1 result instead.
func (s *Server) checkCache(ctx context.Context, req *packet.DNSPacket, cacheKey, _ string, qTypeLabel, protocol string, sendFn func([]byte) error) []byte {
	start := time.Now()
	lock := globalCacheLocks.lockKey(cacheKey)
	lock.Lock()

	// L1 check
	if data, found := s.Cache.GetInto(cacheKey, req.Header.ID); found {
		metrics.CacheOperations.WithLabelValues("l1", "hit").Inc()
		metrics.RecordCacheHit()
		metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
		metrics.QueryDuration.WithLabelValues("cache_l1").Observe(time.Since(start).Seconds())
		lock.Unlock()
		_ = sendFn(data)
		return data
	}
	metrics.CacheOperations.WithLabelValues("l1", "miss").Inc()
	metrics.RecordCacheMiss()

	// L1 miss — check if another goroutine is already fetching L2 for this key
	entry, loading := s.inflightCache.LoadOrStore(cacheKey, &inflightEntry{done: make(chan struct{})})
	if loading {
		// Another goroutine is fetching L2 — release lock and wait for L1 population.
		// Use channel-based wait instead of spinning with time.Sleep.
		lock.Unlock()
		entry := entry.(*inflightEntry)

		// Wait on the in-flight completion channel, with context deadline bounding max wait.
		select {
		case <-entry.done:
			// Fetch completed — L1 should now be populated. Check and return.
		case <-ctx.Done():
			return nil
		}

		// Check L1 cache now that the in-flight goroutine has completed.
		if data, found := s.Cache.GetInto(cacheKey, req.Header.ID); found {
			metrics.CacheOperations.WithLabelValues("l1", "hit").Inc()
			metrics.RecordCacheHit()
			metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
			metrics.QueryDuration.WithLabelValues("cache_l1").Observe(time.Since(start).Seconds())
			_ = sendFn(data)
			return data
		}
		// In-flight goroutine fetched from L2 but got a miss — fall through to DB.
	}

	// Marked in-flight — release lock before L2 fetch
	lock.Unlock()

	// L2 check (Redis) — unlocked for performance
	var data []byte
	var remainingTTL time.Duration
	if s.Redis != nil {
		data, remainingTTL, _ = s.Redis.GetWithTTL(ctx, cacheKey)
	}

	// Re-acquire lock to populate L1, close the in-flight done channel, clear in-flight.
	// Closing done unblocks all goroutines that were waiting on the channel.
	lock.Lock()
	if entry, ok := s.inflightCache.LoadAndDelete(cacheKey); ok {
		close(entry.(*inflightEntry).done)
	}

	// Check L1 again — another goroutine may have populated it while we were fetching L2
	if d, found := s.Cache.GetInto(cacheKey, req.Header.ID); found {
		lock.Unlock()
		_ = sendFn(d)
		return d
	}

	if len(data) > 0 {
		metrics.CacheOperations.WithLabelValues("l2", "hit").Inc()
		metrics.RecordCacheHit()
		metrics.QueriesTotal.WithLabelValues(qTypeLabel, "0", protocol).Inc()
		metrics.QueryDuration.WithLabelValues("cache_l2").Observe(time.Since(start).Seconds())
		if len(data) >= 2 {
			data[0] = byte(req.Header.ID >> 8)
			data[1] = byte(req.Header.ID & 0xFF)
		}
		l1TTLCap := 300 * time.Second
		if v := os.Getenv("REDIS_L1_TTL_CAP"); v != "" {
			if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
				l1TTLCap = time.Duration(secs) * time.Second
			}
		}
		if remainingTTL <= 0 {
			remainingTTL = l1TTLCap
		} else if remainingTTL > l1TTLCap {
			remainingTTL = l1TTLCap
		}
		s.Cache.SetNoCopy(cacheKey, data, remainingTTL)
		lock.Unlock()
		_ = sendFn(data)
		return data
	}

	metrics.CacheOperations.WithLabelValues("l2", "miss").Inc()
	metrics.RecordCacheMiss()
	lock.Unlock()
	return nil
}

// simulateDBLatency adds simulated DB latency if configured.
func (s *Server) simulateDBLatency() {
	if s.SimulateDBLatency <= 0 {
		return
	}
	var b [8]byte
	_, _ = crand.Read(b[:])
	jitter := float64(binary.LittleEndian.Uint64(b[:])) / float64(math.MaxUint64)
	time.Sleep(time.Duration(float64(s.SimulateDBLatency) * (0.5 + jitter)))
}

// processEDNS0 extracts EDNS0 options from the request.
// Returns: clientOPT, maxSize, dnssecOK, nsidRequested, clientCookie, paddingRequested.
func (s *Server) processEDNS0(req *packet.DNSPacket) (*packet.DNSRecord, int, bool, bool, []byte, bool) {
	maxSize := 512
	dnssecOK := false
	nsidRequested := false
	var clientCookie []byte
	paddingRequested := false
	var clientOPT *packet.DNSRecord

	for _, res := range req.Resources {
		if res.Type == packet.OPT {
			clientOPT = &res
			maxSize = int(res.UDPPayloadSize)
			if maxSize < 512 {
				maxSize = 512
			}
			dnssecOK = (res.Z & 0x8000) != 0
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
	return clientOPT, maxSize, dnssecOK, nsidRequested, clientCookie, paddingRequested
}

// newResponseSkeleton creates the response packet with header fields set.
func (s *Server) newResponseSkeleton(req *packet.DNSPacket, q packet.DNSQuestion, clientOPT *packet.DNSRecord, dnssecOK, nsidRequested bool, clientCookie []byte) *packet.DNSPacket {
	response := packet.NewDNSPacket()
	response.Header.ID = req.Header.ID
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Header.RecursionAvailable = s.RecursionEnabled
	response.Questions = append(response.Questions, q)

	if clientOPT != nil {
		opt := packet.DNSRecord{
			Name:           ".",
			Type:           packet.OPT,
			UDPPayloadSize: 4096,
			TTL:            0,
		}
		if dnssecOK {
			opt.Z = 0x8000
		}
		if nsidRequested {
			opt.SetOption(packet.EdnsOptionNSID, []byte(s.NodeID))
		}
		if len(clientCookie) == 8 {
			serverCookie := s.generateServerCookie(clientCookie[:8], "")
			opt.SetOption(packet.EdnsOptionCookie, append(clientCookie[:8], serverCookie...))
		}
		response.Resources = append(response.Resources, opt)
	}
	return response
}

// sendServFail sends a SERVFAIL response when Repo is nil.
func (s *Server) sendServFail(resp *packet.DNSPacket, sendFn func([]byte) error, qTypeLabel, protocol string) error {
	resp.Header.ResCode = packet.RcodeServFail
	metrics.QueriesTotal.WithLabelValues(qTypeLabel, "2", protocol).Inc()
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	_ = resp.Write(resBuffer)
	return sendFn(resBuffer.Buf[:resBuffer.Position()])
}

// resolveWithWildcard attempts wildcard resolution for the query name.
// Returns records and an optional NSEC3 proof record.
func (s *Server) resolveWithWildcard(ctx context.Context, q packet.DNSQuestion, zone *domain.Zone, dnssecOK bool, clientIP string) ([]domain.Record, *packet.DNSRecord) {
	labels := strings.Split(strings.TrimSuffix(q.Name, "."), ".")
	wildcardNames := make([]string, 0, len(labels)-1)
	for i := 0; i < len(labels)-1; i++ {
		wildcardNames = append(wildcardNames, "*."+strings.Join(labels[i+1:], ".")+".")
	}

	results, err := s.Repo.GetRecordsByNames(ctx, wildcardNames, queryTypeToRecordType(q.QType), clientIP)
	if err != nil {
		return nil, nil
	}

	for _, wname := range wildcardNames {
		if recs, ok := results[wname]; ok && len(recs) > 0 {
			for j := range recs {
				recs[j].Name = q.Name // Rewrite wildcard to query name
			}
			// DNSSEC: generate NSEC3 proof for wildcard match
			if dnssecOK {
				nsec3params, _ := s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
				if len(nsec3params) > 0 {
					if nsec3, errNsec := s.generateNSEC3(ctx, zone, q.Name, wname); errNsec == nil {
						return recs, &nsec3
					}
				}
			}
			return recs, nil
		}
	}
	return nil, nil
}

// appendRecordsToResponse converts domain records to packet records and appends to response.
func (s *Server) appendRecordsToResponse(resp *packet.DNSPacket, records []domain.Record) {
	for _, rec := range records {
		if pRec, err := repository.ConvertDomainToPacketRecord(rec); err == nil {
			resp.Answers = append(resp.Answers, pRec)
		}
	}
}

// handleNxDomain handles the NXDOMAIN / NoData case.
func (s *Server) handleNxDomain(ctx context.Context, req *packet.DNSPacket, q packet.DNSQuestion, zone *domain.Zone, dnssecOK bool, clientOPT *packet.DNSRecord, clientIP string, resp *packet.DNSPacket) {
	if zone != nil {
		resp.Header.ResCode = 3 // NXDOMAIN

		// Parallelize SOA and NSEC3PARAM lookups — both are independent DB calls
		var soaRecords []domain.Record
		var nsec3params []domain.Record
		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(2)
		g.Go(func() error {
			var err error
			soaRecords, err = s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, clientIP)
			return err
		})
		g.Go(func() error {
			if !dnssecOK {
				return nil
			}
			var err error
			nsec3params, err = s.Repo.GetRecords(ctx, zone.Name, "NSEC3PARAM", "")
			return err
		})
		_ = g.Wait()

		for _, rec := range soaRecords {
			if pRec, err := repository.ConvertDomainToPacketRecord(rec); err == nil {
				resp.Authorities = append(resp.Authorities, pRec)
			}
		}
		if dnssecOK {
			if len(nsec3params) > 0 {
				if nsec, err := s.generateNSEC3(ctx, zone, q.Name, ""); err == nil {
					resp.Authorities = append(resp.Authorities, nsec)
				}
			} else {
				if nsec, err := s.generateNSEC(ctx, zone, q.Name); err == nil {
					resp.Authorities = append(resp.Authorities, nsec)
				}
			}
		}
	} else {
		if s.RecursionEnabled && req.Header.RecursionDesired {
			if recursiveResp, err := s.resolveRecursive(ctx, q.Name, q.QType); err == nil && recursiveResp != nil {
				resp.Header.AuthoritativeAnswer = false
				resp.Header.ResCode = recursiveResp.Header.ResCode
				resp.Answers = recursiveResp.Answers
				resp.Authorities = recursiveResp.Authorities
			} else {
				resp.Header.AuthoritativeAnswer = false
				resp.Header.ResCode = 2 // SERVFAIL
			}
		} else {
			resp.Header.AuthoritativeAnswer = false
			resp.Header.ResCode = 3 // NXDOMAIN
		}
	}

	// RFC 8914: Add EDE for NXDOMAIN
	if clientOPT != nil {
		for i := range resp.Resources {
			if resp.Resources[i].Type == packet.OPT {
				resp.Resources[i].AddEDE(packet.EdeOther, "")
			}
		}
	}
}

// populateAuthorityAndAdditional adds NS records and glue A records to the response.
func (s *Server) populateAuthorityAndAdditional(ctx context.Context, resp *packet.DNSPacket, zone *domain.Zone, clientIP string) {
	nsRecords, _ := s.Repo.GetRecords(ctx, zone.Name, domain.TypeNS, clientIP)
	nsTargets := make([]string, 0, len(nsRecords))
	for _, rec := range nsRecords {
		if pRec, err := repository.ConvertDomainToPacketRecord(rec); err == nil {
			nsTargets = append(nsTargets, pRec.Host)
		}
	}

	allGlue, _ := s.Repo.GetRecordsByNames(ctx, nsTargets, domain.TypeA, clientIP)

	for _, rec := range nsRecords {
		if pRec, err := repository.ConvertDomainToPacketRecord(rec); err == nil {
			resp.Authorities = append(resp.Authorities, pRec)
			for _, gRec := range allGlue[pRec.Host] {
				if gpRec, err := repository.ConvertDomainToPacketRecord(gRec); err == nil {
					resp.Resources = append(resp.Resources, gpRec)
				}
			}
		}
	}
}

// validateDNSSECResponse performs DNSSEC validation and converts to SERVFAIL in strict mode.
func (s *Server) validateDNSSECResponse(ctx context.Context, zone *domain.Zone, resp *packet.DNSPacket) {
	if err := s.validateDNSSEC(ctx, zone.Name, resp); err != nil && s.DNSSECMode == "strict" {
		resp.Header.ResCode = packet.RcodeServFail
		resp.Answers = nil
		resp.Authorities = nil
		for i := range resp.Resources {
			if resp.Resources[i].Type == packet.OPT {
				resp.Resources[i].AddEDE(packet.EdeDnssecBogus, err.Error())
			}
		}
	}
}

// extractMaxSizeFromOPT re-reads maxSize from the request's OPT record.
func (s *Server) extractMaxSizeFromOPT(req *packet.DNSPacket, fallback int) int {
	for _, res := range req.Resources {
		if res.Type == packet.OPT {
			ms := int(res.UDPPayloadSize)
			if ms < 512 {
				ms = 512
			}
			return ms
		}
	}
	return fallback
}

// truncateIfNeeded applies RFC 6891 multi-pass truncation to the response.
func (s *Server) truncateIfNeeded(resp *packet.DNSPacket, buf *packet.BytePacketBuffer, maxSize int) {
	if buf.Position() <= maxSize {
		return
	}
	resp.Header.TruncatedMessage = true
	resp.Answers = nil
	resp.Authorities = nil
	// Preserve OPT records
	var optRecords []packet.DNSRecord
	for _, res := range resp.Resources {
		if res.Type == packet.OPT {
			optRecords = append(optRecords, res)
		}
	}
	resp.Resources = optRecords
	buf.Reset()
	buf.HasNames = true
	_ = resp.Write(buf)
	// If still too large, remove OPT entirely
	if buf.Position() > maxSize {
		resp.Resources = nil
		buf.Reset()
		buf.HasNames = true
		_ = resp.Write(buf)
	}
}

// cacheResult caches the response in L1 and L2 if eligible.
func (s *Server) cacheResult(ctx context.Context, cacheKey string, resData []byte, resp *packet.DNSPacket) {
	if resp.Header.TruncatedMessage || (resp.Header.ResCode != 0 && resp.Header.ResCode != 3) {
		return
	}
	var ttl uint32 = 300
	if len(resp.Answers) > 0 {
		ttl = resp.Answers[0].TTL
	} else if len(resp.Authorities) > 0 {
		ttl = resp.Authorities[0].TTL
	}
	// RFC 2308: NXDOMAIN uses SOA MINIMUM for negative cache TTL
	if resp.Header.ResCode == 3 {
		for _, auth := range resp.Authorities {
			if auth.Type == packet.SOA {
				ttl = min(auth.Minimum, auth.TTL)
				break
			}
		}
	}
	cacheData := make([]byte, len(resData))
	copy(cacheData, resData)
	s.Cache.Set(cacheKey, cacheData, time.Duration(ttl)*time.Second)
	if s.Redis != nil {
		s.Redis.Set(ctx, cacheKey, cacheData, time.Duration(ttl)*time.Second)
	}
}

// handleNotify processes a DNS NOTIFY (RFC 1996) and triggers a zone refresh if needed.
func (s *Server) handleNotify(ctx context.Context, request *packet.DNSPacket, clientIP string, sendFn func([]byte) error) error {
	if len(request.Questions) == 0 {
		s.Logger.Warn("received NOTIFY without questions", "from", clientIP)
		return nil
	}
	s.Logger.Info("received NOTIFY", "zone", request.Questions[0].Name, "from", clientIP)
	metrics.NotifiesTotal.WithLabelValues(request.Questions[0].Name, "accepted").Inc()

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeNotify
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, request.Questions[0])

	// For slave zones, validate source is the configured master before triggering refresh
	zone, err := s.Repo.GetZone(ctx, request.Questions[0].Name)
	if err != nil {
		s.Logger.Error("failed to fetch zone for notify", "zone", request.Questions[0].Name, "error", err)
	}
	if zone != nil && zone.Role == "slave" && zone.MasterServer != "" {
		if !isAuthorizedNotifier(clientIP, zone.MasterServer) {
			s.Logger.Warn("NOTIFY rejected: unauthorized source", "from", clientIP, "master", zone.MasterServer)
		} else if !s.DisableAsync {
			go func(zoneName string) {
				select {
				case <-ctx.Done():
					return
				case <-s.done:
					return
				default:
				}
				if z, err := s.Repo.GetZone(ctx, zoneName); err == nil && z != nil {
					s.refreshZone(ctx, z)
				}
			}(request.Questions[0].Name)
		}
	}

	response.Header.ResCode = packet.RcodeNoError
	return s.sendUpdateResponse(response, sendFn)
}

// isAuthorizedNotifier checks if the source IP is authorized to send NOTIFY for the zone.
func isAuthorizedNotifier(clientIP, masterServer string) bool {
	// Extract host from masterServer (may be "host:port" format)
	masterHost, _, err := net.SplitHostPort(masterServer)
	if err != nil {
		masterHost = masterServer // No port in config, use as-is
	}

	// If master is an IP, compare directly
	if net.ParseIP(masterHost) != nil {
		return clientIP == masterHost
	}

	// Master is a hostname — resolve and compare IPs
	addrs, err := net.ResolveTCPAddr("tcp", masterHost+":0")
	if err != nil {
		return false
	}
	clientParsed := net.ParseIP(clientIP)
	if clientParsed == nil {
		return false
	}
	return clientParsed.Equal(addrs.IP)
}

// handleUpdate processes a DNS dynamic update (RFC 2136) request.
func (s *Server) handleUpdate(ctx context.Context, request *packet.DNSPacket, rawData []byte, clientIP string, sendFn func([]byte) error) error {
	s.Logger.Info("handling dynamic update", "id", request.Header.ID, "client", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeUpdate

	// 1. Validate TSIG if present
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Debug("update failed: unknown TSIG key", "key", tsig.Name)
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

// handleIXFR processes an incremental zone transfer (IXFR) request over TCP.
func (s *Server) handleIXFR(ctx context.Context, conn net.Conn, request *packet.DNSPacket, rawData []byte, buffer *packet.BytePacketBuffer) {
	defer packet.PutBuffer(buffer)
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Validate TSIG if present
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		secret, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Debug("IXFR failed: unknown TSIG key", "key", tsig.Name, "zone", q.Name)
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

// signResponse signs a DNS response with the zone's DNSSEC keys.
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

	// Build and validate the trust chain from leaf to trust anchor
	chain, chainErr := s.buildDNSSECChain(ctx, zoneName)
	if chainErr != nil {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: failed to build trust chain: %w", chainErr)
		}
		// Non-strict: fall through to RRset result below
	} else if validateErr := s.DNSSECValidator.ValidateChain(chain, now); validateErr != nil {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: trust chain validation failed: %w", validateErr)
		}
		// Chain invalid in non-strict mode — AD bit must be false, not allValid
		response.Header.AuthedData = false
		return nil
	} else {
		// Chain valid — but AD requires both chain AND per-RRset validation to succeed
		if s.DNSSECMode == "strict" && !allValid {
			return fmt.Errorf("dnssec: chain valid but per-RRset validation failed")
		}
		response.Header.AuthedData = allValid
		return nil
	}

	response.Header.AuthedData = allValid
	return nil
}

// fetchDNSKEYFromNetwork queries DNSKEY records for a zone from the network.
// It returns the DNSKEY records and an error if the query failed.
func (s *Server) fetchDNSKEYFromNetwork(ctx context.Context, zoneName string) ([]packet.DNSRecord, error) {
	// First try to resolve DNSKEY via recursive resolution
	dnskeyResp, err := s.resolveRecursive(ctx, zoneName, packet.DNSKEY)
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

// fetchDSFromNetwork queries DS records for a child zone from the parent zone.
// It also fetches the RRSIG records that sign the DS RRset.
func (s *Server) fetchDSFromNetwork(ctx context.Context, childZone, parentZone string) ([]packet.DNSRecord, []packet.DNSRecord, error) {
	// Query for the child zone's DS record (from the parent zone's authority)
	dsResp, err := s.resolveRecursive(ctx, childZone, packet.DS)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve DS for %s from %s: %w", childZone, parentZone, err)
	}

	var dsRecords []packet.DNSRecord
	var rrsigDSRecords []packet.DNSRecord

	// Collect DS records matching the child zone
	for _, rec := range dsResp.Answers {
		if rec.Type == packet.DS && strings.EqualFold(rec.Name, childZone) {
			dsRecords = append(dsRecords, rec)
		}
		if rec.Type == packet.RRSIG && rec.TypeCovered == uint16(packet.DS) {
			rrsigDSRecords = append(rrsigDSRecords, rec)
		}
	}

	// RRSIG_DS may also be in authorities section
	for _, rec := range dsResp.Authorities {
		if rec.Type == packet.RRSIG && rec.TypeCovered == uint16(packet.DS) {
			rrsigDSRecords = append(rrsigDSRecords, rec)
		}
	}

	return dsRecords, rrsigDSRecords, nil
}

// buildDNSSECChain builds a trust chain from leaf zone to trust anchor by walking
// parent zones and collecting DNSKEYs, DS records, and RRSIG_DS records.
// It stops when it reaches a zone that matches a configured trust anchor.
func (s *Server) buildDNSSECChain(ctx context.Context, zoneName string) ([]services.ChainLink, error) {
	if s.DNSSECValidator == nil {
		return nil, fmt.Errorf("dnssec: no validator configured")
	}

	var chain []services.ChainLink
	currentZone := zoneName

	// Max depth to prevent infinite loops (root + 2-3 levels of typical delegation)
	const maxDepth = 10

	for len(chain) < maxDepth {
		// Fetch DNSKEYs for current zone
		dnskeyRecs, err := s.fetchDNSKEYFromNetwork(ctx, currentZone)
		if err != nil {
			return nil, fmt.Errorf("buildDNSSECChain: failed to fetch DNSKEYs for %s: %w", currentZone, err)
		}

		link := services.ChainLink{
			Zone:    currentZone,
			DNSKEYs: dnskeyRecs,
		}

		// If we have a parent, fetch DS + RRSIG_DS from parent
		parentZone := parentZoneName(currentZone)
		if parentZone != "" && parentZone != "." {
			dsRecs, rrsigDSRecs, dsErr := s.fetchDSFromNetwork(ctx, currentZone, parentZone)
			if dsErr != nil {
				return nil, fmt.Errorf("buildDNSSECChain: failed to fetch DS for %s from %s: %w", currentZone, parentZone, dsErr)
			}
			// Take the first DS record (zones typically have one DS per signing key)
			if len(dsRecs) > 0 {
				link.DS = dsRecs[0]
			}
			link.RRSIGsDS = rrsigDSRecs
		}

		chain = append(chain, link)

		// Check if current zone is a trust anchor
		if s.DNSSECValidator.GetTrustAnchor(currentZone) != nil {
			break
		}

		// Move to parent zone
		if parentZone == "" || parentZone == "." {
			break
		}
		currentZone = parentZone
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("buildDNSSECChain: could not build chain for %s", zoneName)
	}

	return chain, nil
}

// parentZoneName returns the parent zone name for a given zone.
// e.g., "www.example.com." -> "example.com." -> "com." -> "." -> ""
// For root zone ("."), returns "" as root has no parent.
func parentZoneName(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return "" // Root zone has no parent
	}
	labels := strings.Split(zone, ".")
	if len(labels) < 2 {
		return "."
	}
	if len(labels) == 2 {
		return labels[len(labels)-1] + "."
	}
	return strings.Join(labels[1:], ".") + "."
}

// groupRecords groups DNS records by name and type for response assembly.
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

// sendSingleRecordResponse sends a TCP DNS response containing a single resource record.
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

// sendUpdateResponse serializes and sends a DNS UPDATE response.
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

// checkPrerequisite evaluates a DNS UPDATE prerequisite record (RFC 2136 Section 2.4).
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

// notifySlaves sends DNS NOTIFY messages to all slave servers configured for a zone.
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

// generateNSEC creates an NSEC record proving no records exist for a name (DNSSEC).
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

// generateNSEC3 creates an NSEC3 record for a query name (DNSSEC with NSEC3).
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

// generateTypeBitMap creates the NSEC3 type bitmap window blocks.
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

// queryTypeToRecordType converts a packet query type to a domain record type.
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
