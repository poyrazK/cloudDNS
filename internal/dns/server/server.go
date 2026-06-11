package server

import (
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/config"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
	"github.com/quic-go/quic-go"
)

// ClassCHAOS is the DNS class for server identity and metadata.
const ClassCHAOS = 3

// IXFR limits to prevent memory exhaustion from unbounded chunk processing.
const (
	MaxIXFRChunks      = 1000  // max chunks per IXFR response
	MaxRecordsPerChunk = 10000 // max records per chunk Deleted/Added arrays
	MaxAXFRRecords     = 50000 // max records in AXFR fallback or NSEC generation
)

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
	TsigKeys         map[string]TsigKey
	NodeID           string
	RecursionEnabled bool
	CookieSecret     []byte

	// DNS64Enabled enables DNS64 synthesis (RFC 6147).
	// When enabled and an AAAA query returns NODATA, the server synthesizes
	// AAAA records from existing A records using the configured DNS64Prefix.
	DNS64Enabled bool
	DNS64Prefix  net.IP

	// Testing/Chaos flags
	SimulateDBLatency  time.Duration
	NotifyPortOverride int
	DisableAsync       bool // If true, NOTIFY and UPDATE handlers won't spawn goroutines

	// TLS Config for DoT, DoH, and DoQ
	TLSConfig *tls.Config
	DoQAddr  string // DNS-over-QUIC listen address (default ":853")

	// Catalog Zone Polling (RFC 9432 slave-side)
	CatalogPollingEnabled bool
	CatalogZones         []string // catalog zone names to poll
	CatalogMasterAddr    string   // master server address (host:port)
	CatalogPollInterval  time.Duration
	CatalogTenantID      string   // tenant ID for catalog-provisioned zones

	// ServerConfig holds timeout and timing values.
	ServerConfig *config.ServerConfig

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

	// catalogState tracks the last-seen serial for each catalog zone to avoid unnecessary re-syncs
	catalogState *catalogPollerState

	// inflightCache prevents thundering herd: tracks keys currently being fetched from L2.
	// Key -> *inflightEntry (done channel closed when fetch completes).
	inflightCache sync.Map

	// l1TTLCap is cached at startup to avoid repeated os.Getenv calls in hot path
	l1TTLCap time.Duration

	// querySingleflight ensures only one goroutine performs DB query per cache key.
	querySingleflight singleflight.Group
}

// catalogPollerState tracks catalog zone polling state for efficient change detection.
type catalogPollerState struct {
	mu             sync.RWMutex
	lastSeenSerial map[string]uint32    // catalogZoneName -> serial
	lastSeenAt     map[string]time.Time // catalogZoneName -> last update time (for TTL eviction)
}

// cleanup removes stale entries older than ttl from the catalog state.
func (s *catalogPollerState) cleanup(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-ttl)
	for name, t := range s.lastSeenAt {
		if t.Before(cutoff) {
			delete(s.lastSeenSerial, name)
			delete(s.lastSeenAt, name)
		}
	}
}

// parseCatalogZones parses a comma-separated list of zone names.
func parseCatalogZones(env string) []string {
	if env == "" {
		return nil
	}
	var zones []string
	for _, z := range strings.Split(env, ",") {
		z = strings.TrimSpace(z)
		if z != "" {
			zones = append(zones, z)
		}
	}
	return zones
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

	// Catalog polling configuration (RFC 9432 slave-side)
	catalogPollingEnabled := os.Getenv("CATALOG_POLLING_ENABLED") == "true"
	catalogZones := parseCatalogZones(os.Getenv("CATALOG_ZONES"))
	catalogMasterAddr := os.Getenv("CATALOG_MASTER_ADDR")
	catalogPollInterval := 5 * time.Minute
	if interval := os.Getenv("CATALOG_POLL_INTERVAL"); interval != "" {
		if d, err := time.ParseDuration(interval); err == nil {
			catalogPollInterval = d
		}
	}
	catalogTenantID := os.Getenv("CATALOG_TENANT_ID")

	s := &Server{
		Addr:                 addr,
		Repo:                 repo,
		WorkerCount:          runtime.NumCPU() * 32, // High concurrency tuning
		udpQueue:             make(chan udpTask, 50000),
		Logger:               logger,
		limiter:              newRateLimiter(500000, 200000, 1000000),
		TsigKeys:             make(map[string]TsigKey),
		NodeID:               nodeID,
		RecursionEnabled:     recursion,
		CookieSecret:         make([]byte, 32),
		catalogState:         &catalogPollerState{lastSeenSerial: make(map[string]uint32), lastSeenAt: make(map[string]time.Time)},
		CatalogPollingEnabled: catalogPollingEnabled,
		CatalogZones:         catalogZones,
		CatalogMasterAddr:    catalogMasterAddr,
		CatalogPollInterval:  catalogPollInterval,
		CatalogTenantID:      catalogTenantID,
	}
	s.lifecycleCtx, s.cancel = context.WithCancel(context.Background())
	s.done = make(chan struct{})
	_, _ = crand.Read(s.CookieSecret)
	s.queryFn = s.sendQuery

	// Cache REDIS_L1_TTL_CAP at startup to avoid repeated os.Getenv in hot path
	s.l1TTLCap = 300 * time.Second
	if v := os.Getenv("REDIS_L1_TTL_CAP"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			s.l1TTLCap = time.Duration(secs) * time.Second
		}
	}

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

// startInvalidationListener listens for cache invalidation events from Redis pub/sub.
func (s *Server) startInvalidationListener(ctx context.Context, done <-chan struct{}) {
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
		case <-done:
			s.Logger.Info("stopping global cache invalidation listener via done")
			return
		case <-ctx.Done():
			s.Logger.Info("stopping global cache invalidation listener")
			return
		case msg := <-ch:
			// msg.Payload format is "tenant_id:name:type" for record-level
			// or "tenant_id:name" for zone-level (NEW format with tenant_id)
			// Legacy format without tenant_id: "name:type" or just "name"
			s.Logger.Debug("received cache invalidation event", "key", msg.Payload)

			// Split into up to 3 parts: tenant_id:name:type
			parts := strings.SplitN(msg.Payload, ":", 3)

			// Determine if this is a zone-level or record-level invalidation
			if len(parts) == 1 || (len(parts) == 2 && parts[1] == "") {
				// Zone-level invalidation: "tenant_id:name" or legacy "name"
				var tenantID, zoneName string
				if len(parts) == 2 {
					tenantID, zoneName = parts[0], parts[1]
				} else {
					// Legacy format - do zone lookup
					zoneName = msg.Payload
					if s.Repo != nil {
						if zone, err := s.Repo.GetZoneLongestMatch(ctx, zoneName); err == nil && zone != nil {
							tenantID = zone.TenantID
						}
					}
				}
				s.Logger.Debug("zone-level cache invalidation, flushing L1", "zone", zoneName, "tenant", tenantID)
				s.Cache.Flush()
				if s.Redis != nil {
					if tenantID != "" {
						_ = s.Redis.client.Del(ctx, "dns:"+tenantID+":"+zoneName+":").Err()
					} else {
						_ = s.Redis.client.Del(ctx, "dns:"+zoneName+":").Err()
					}
				}
				continue
			}

			// Record-level invalidation
			// Standardize key for L1 cache lookup (lowercase name)
			// New format: tenant_id:name:type (3 parts)
			// Legacy format: name:type (2 parts)
			parts = strings.SplitN(msg.Payload, ":", 3)
			var nameLower, tenantID string
			var qType int

			if len(parts) == 3 {
				// New format: tenant_id:name:type
				tenantID = parts[0]
				nameLower = strings.ToLower(parts[1])
				qType = int(packet.RecordTypeToQueryType(domain.RecordType(parts[2])))
			} else if len(parts) == 2 {
				// Legacy format: name:type — need to look up tenant_id via zone lookup
				nameLower = strings.ToLower(parts[0])
				qType = int(packet.RecordTypeToQueryType(domain.RecordType(parts[1])))

				if s.Repo != nil {
					zone, err := s.Repo.GetZoneLongestMatch(ctx, parts[0])
					if err == nil && zone != nil {
						tenantID = zone.TenantID
					}
				}
			} else {
				s.Logger.Warn("malformed cache invalidation payload, dropping", "payload", msg.Payload)
				continue
			}

			if tenantID != "" {
				// Build tenant-aware cache key
				l1Key := fmt.Sprintf("%s:%s:%d", tenantID, nameLower, qType)
				if s.Cache == nil {
					s.Logger.Warn("cache is nil, pushing to DLQ", "key", l1Key)
					if errDLQ := s.Redis.PushToDLQ(ctx, msg.Payload); errDLQ != nil {
						s.Logger.Error("failed to push nil-cache message to DLQ", "error", errDLQ)
					}
					continue
				}
				s.Cache.Invalidate(l1Key)
				if s.Redis != nil {
					_ = s.Redis.client.Del(ctx, "dns:"+l1Key).Err()
				}
			} else {
				// No tenant (recursive query cache) — use recursive prefix
				l1Key := fmt.Sprintf("recursive:%s:%d", nameLower, qType)
				if s.Cache != nil {
					s.Cache.Invalidate(l1Key)
				}
				if s.Redis != nil {
					_ = s.Redis.client.Del(ctx, "dns:"+l1Key).Err()
				}
			}
		}
	}
}

// dlqRetryWorker processes messages from the dead letter queue with retry logic.
// It runs until the context is canceled.
func (s *Server) dlqRetryWorker(ctx context.Context, done <-chan struct{}) {
	s.Logger.Info("starting DLQ retry worker")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			s.Logger.Info("stopping DLQ retry worker via done")
			return
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
		// New format: tenant_id:name:type (3 parts)
		// Legacy format: name:type (2 parts)
		parts := strings.SplitN(msg, ":", 3)
		var nameLower, tenantID string
		var qType int

		if len(parts) == 3 {
			// New format: tenant_id:name:type
			tenantID = parts[0]
			nameLower = strings.ToLower(parts[1])
			qType = int(packet.RecordTypeToQueryType(domain.RecordType(parts[2])))
		} else if len(parts) == 2 {
			// Legacy format: name:type — need to look up tenant_id via zone lookup
			nameLower = strings.ToLower(parts[0])
			qType = int(packet.RecordTypeToQueryType(domain.RecordType(parts[1])))

			if s.Repo != nil {
				zone, err := s.Repo.GetZoneLongestMatch(ctx, parts[0])
				if err == nil && zone != nil {
					tenantID = zone.TenantID
				}
			}
		} else {
			s.Logger.Warn("DLQ message malformed, dropping", "msg", msg)
			continue
		}

		var l1Key string
		if tenantID != "" {
			l1Key = fmt.Sprintf("%s:%s:%d", tenantID, nameLower, qType)
		} else {
			l1Key = fmt.Sprintf("recursive:%s:%d", nameLower, qType)
		}

		if s.Cache != nil {
			s.Cache.Invalidate(l1Key)
			s.Logger.Debug("DLQ message processed successfully", "key", l1Key)
		} else {
			s.Logger.Warn("cache still nil, dropping DLQ message", "key", l1Key)
		}
	}
}


// udpReadDeadline is the read deadline set on UDP sockets to allow periodic
// re-checking of the shutdown signal (s.done). Without this, ReadFrom blocks
// indefinitely and goroutines don't exit promptly on cancellation.
func (s *Server) udpReadDeadline() time.Duration {
	if s.ServerConfig != nil {
		return s.ServerConfig.UDPSocketReadDeadline
	}
	return 500 * time.Millisecond
}

// shutdownTimeout returns the configured shutdown timeout, defaulting to 5s.
func (s *Server) shutdownTimeout() time.Duration {
	if s.ServerConfig != nil {
		return s.ServerConfig.ShutdownTimeout
	}
	return 5 * time.Second
}

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
		if s.doqListener != nil {
			if err := s.doqListener.Close(); err != nil {
				s.Logger.Warn("failed to close DoQ listener", "error", err)
			}
		}
		s.wg.Wait()  // Wait for all goroutines to finish before Run() returns
		// Shutdown HTTP servers and Redis (can take time, so separate from wg wait)
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
		defer shutdownCancel()
		if s.dohServer != nil {
			if err := s.dohServer.Shutdown(shutdownCtx); err != nil { //nolint:contextcheck
				s.Logger.Warn("failed to shut down DoH server", "error", err)
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
			s.startInvalidationListener(ctx, s.done)
		}()

		// Start DLQ retry worker
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.dlqRetryWorker(ctx, s.done)
		}()
	}

	// Start catalog zone poller if configured (RFC 9432 slave-side)
	if s.CatalogPollingEnabled && len(s.CatalogZones) > 0 {
		if s.CatalogMasterAddr == "" {
			s.Logger.Warn("catalog polling enabled but CATALOG_MASTER_ADDR not set, skipping")
		} else {
			s.Logger.Info("starting catalog zone poller",
				"zones", s.CatalogZones,
				"master", s.CatalogMasterAddr,
				"interval", s.CatalogPollInterval,
				"tenant", s.CatalogTenantID,
			)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.StartCatalogPoller(s.lifecycleCtx, s.CatalogZones, s.CatalogMasterAddr, s.CatalogPollInterval)
			}()
		}
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
			_ = c.SetReadDeadline(time.Now().Add(s.udpReadDeadline()))
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
						_ = c.SetReadDeadline(time.Now().Add(s.udpReadDeadline()))
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
	// Close listeners to unblock workers before wg.Wait() in defer
	if s.tcpListener != nil {
		_ = s.tcpListener.Close()
	}
	if s.dotListener != nil {
		_ = s.dotListener.Close()
	}
	if s.doqListener != nil {
		_ = s.doqListener.Close()
	}
	return nil
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

	// CHAOS identity queries - compute lowerName once
	lowerName := strings.ToLower(q.Name)
	if q.QClass == ClassCHAOS {
		if lowerName == "id.server." || lowerName == "hostname.bind." {
			return s.sendCHAOSIdentity(request, q, sendFn, qTypeLabel, protocol)
		}
	}

	// Standardize name
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Zone lookup to get tenant_id for cache key (before cache check)
	var tenantID string
	zone, errZone := s.Repo.GetZoneLongestMatch(ctx, q.Name)
	if errZone == nil && zone != nil {
		tenantID = zone.TenantID
	}

	// Create tenant-aware cache key
	var cacheKey string
	if tenantID != "" {
		cacheKey = tenantID + ":" + lowerName + ":" + strconv.Itoa(int(q.QType))
	} else {
		// Recursive or no-zone query — use special prefix
		cacheKey = "recursive:" + lowerName + ":" + strconv.Itoa(int(q.QType))
	}

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

	// Issue #254: Use singleflight to prevent thundering herd on cache miss.
	// Only one goroutine performs the DB query, others wait for the result.
	queryResult, _, _ := s.querySingleflight.Do(cacheKey, func() (interface{}, error) {
		result := s.queryDB(ctx, &q, clientIP)
		return result, nil
	})
	result := queryResult.(*queryDBResult)
	zone, records, errRepo := result.zone, result.records, result.err

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

		// DNS64 synthesis (RFC 6147) - only for authoritative NODATA
		if s.DNS64Enabled && q.QType == packet.AAAA && zone != nil {
			s.synthesizeDNS64(ctx, q, clientIP, response)
		}
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

	// Use maxSize from processEDNS0 — clientOPT already has the correct payload size.
	// No second O(n) scan needed.
	if clientOPT != nil && clientOPT.UDPPayloadSize >= 512 {
		maxSize = int(clientOPT.UDPPayloadSize)
	}

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

	// Issue #235: If wildcard resolution occurred, rebuild cache key with zone's tenantID
	// to ensure proper tenant isolation (original cacheKey may have been built before
	// we knew which zone would serve the wildcard match)
	if source == "wildcard" && zone != nil && zone.TenantID != "" {
		cacheKey = zone.TenantID + ":" + lowerName + ":" + strconv.Itoa(int(q.QType))
	}

	// Cache result
	s.cacheResult(ctx, cacheKey, resData, response)

	metrics.QueriesTotal.WithLabelValues(qTypeLabel, fmt.Sprintf("%d", response.Header.ResCode), protocol).Inc()
	s.Logger.Info("query processed", "name", q.Name, "src", source, "lat", time.Since(start).Milliseconds())
	return sendFn(resData)
}

// queryDB performs zone and record lookups in parallel. Used by singleflight to prevent thundering herd.
func (s *Server) queryDB(ctx context.Context, q *packet.DNSQuestion, clientIP string) *queryDBResult {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(2)

	var zone *domain.Zone
	var records []domain.Record
	var errRepo error

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

	return &queryDBResult{zone: zone, records: records, err: errRepo}
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
		l1TTLCap := s.l1TTLCap
		if remainingTTL <= 0 {
			remainingTTL = l1TTLCap
		} else if remainingTTL > l1TTLCap {
			remainingTTL = l1TTLCap
		}
		s.Cache.Set(cacheKey, data, remainingTTL)
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

	// Fetch NS and A glue in parallel — GetRecordsByNames is a no-op when nsTargets is empty.
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(2)
	var allGlue map[string][]domain.Record
	g.Go(func() error {
		var err error
		allGlue, err = s.Repo.GetRecordsByNames(ctx, nsTargets, domain.TypeA, clientIP)
		return err
	})
	_ = g.Wait()

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
// In non-strict mode, it still removes data with invalid signatures for security.
func (s *Server) validateDNSSECResponse(ctx context.Context, zone *domain.Zone, resp *packet.DNSPacket) {
	if err := s.validateDNSSEC(ctx, zone.Name, resp); err != nil {
		if s.DNSSECMode == "strict" {
			resp.Header.ResCode = packet.RcodeServFail
			resp.Answers = nil
			resp.Authorities = nil
			for i := range resp.Resources {
				if resp.Resources[i].Type == packet.OPT {
					// Use EDE code only (empty string) to avoid leaking internal error details
					resp.Resources[i].AddEDE(packet.EdeDnssecBogus, "")
				}
			}
		} else {
			// Non-strict mode: return SERVFAIL and remove data with invalid signatures
			resp.Header.ResCode = packet.RcodeServFail
			resp.Header.AuthedData = false
			resp.Answers = nil
			resp.Authorities = nil
		}
	}
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
	// DNS64 synthesized responses should not be cached (or use very short TTL)
	// per RFC 6147 Section 5. Use 1 second TTL as a compromise.
	if resp.Header.DNS64Synthesized {
		ttl = 1
	} else if len(resp.Answers) > 0 {
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


// synthesizeDNS64 performs DNS64 synthesis (RFC 6147).
// Called when a query for AAAA returns NODATA but we have an authoritative zone.
func (s *Server) synthesizeDNS64(ctx context.Context, q packet.DNSQuestion, clientIP string, resp *packet.DNSPacket) {
	aRecords, err := s.Repo.GetRecords(ctx, q.Name, domain.TypeA, clientIP)
	if err != nil || len(aRecords) == 0 {
		return
	}
	var aPacketRecords []packet.DNSRecord
	minTTL := uint32(300)
	for _, rec := range aRecords {
		if pRec, err := repository.ConvertDomainToPacketRecord(rec); err == nil {
			aPacketRecords = append(aPacketRecords, pRec)
			if rec.TTL < int(minTTL) {
				minTTL = uint32(rec.TTL)
			}
		}
	}
	if len(aPacketRecords) == 0 {
		return
	}
	synthesizer := NewDNS64Synthesizer(s.DNS64Prefix)
	aaaaRecords := synthesizer.SynthesizeAAAA(aPacketRecords, q.Name, minTTL)
	if len(aaaaRecords) > 0 {
		resp.Answers = append(resp.Answers, aaaaRecords...)
		resp.Header.ResCode = 0       // NoError instead of NXDOMAIN
		resp.Header.AuthoritativeAnswer = true
		resp.Header.DNS64Synthesized = true
	}
}
