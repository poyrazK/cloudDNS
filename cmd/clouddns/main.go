// clouddns is the main DNS server daemon for cloudDNS.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/api"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/adapters/routing"
	"github.com/poyrazK/cloudDNS/internal/core/config"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

// main is the entry point for the cloudDNS daemon.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx); err != nil {
		slog.Error("application failed", "error", err)
		os.Exit(1)
	}
}

// replaceSSLMode replaces sslmode values in DSN format string with the given mode.
// Only matches space-delimited parameters to avoid matching sslmode within values.
func replaceSSLMode(dbURL, mode string) string {
	// Replace existing sslmode values (only as separate space-delimited params)
	dbURL = replaceDSNParam(dbURL, "sslmode", mode)
	if !strings.Contains(dbURL, "sslmode=") {
		dbURL += " sslmode=" + mode
	}
	return dbURL
}

// replaceDSNParam replaces a parameter in DSN format (space-separated key=value pairs).
// Only replaces exact param matches to avoid matching within values.
func replaceDSNParam(dbURL, param, value string) string {
	parts := strings.Fields(dbURL)
	for i, p := range parts {
		if strings.HasPrefix(p, param+"=") {
			parts[i] = param + "=" + value
		}
	}
	return strings.Join(parts, " ")
}

// processDatabaseURL applies DATABASE_HOST overrides and SSL mode settings.
// It handles both URL format (postgres://...) and DSN format (user=...).
// Exported for testing.
func processDatabaseURL(dbURL, hostOverride string) string {
	if dbURL == "" {
		return "" // Require explicit DATABASE_URL
	}

	if hostOverride == "" {
		return dbURL
	}

	// Detect URL format vs DSN format by checking for postgres:// prefix
	isURL := strings.HasPrefix(dbURL, "postgres://") || strings.HasPrefix(dbURL, "postgresql://")
	if isURL {
		u, err := url.Parse(dbURL)
		if err != nil {
			slog.Warn("failed to parse database URL", "error", err)
		} else {
			u.Host = hostOverride
			q := u.Query()
			if hostOverride == "127.0.0.1" || hostOverride == "localhost" || hostOverride == "::1" {
				q.Set("sslmode", "disable")
			}
			u.RawQuery = q.Encode()
			return u.String()
		}
	}
	// DSN format (user=... password=... host=... etc)
	isLocalHost := hostOverride == "127.0.0.1" || hostOverride == "localhost" || hostOverride == "::1"
	if isLocalHost {
		dbURL = replaceSSLMode(dbURL, "disable")
	}
	if strings.Contains(dbURL, "host=") {
		parts := strings.Split(dbURL, " ")
		for i, p := range parts {
			if strings.HasPrefix(p, "host=") {
				parts[i] = "host=" + hostOverride
			}
		}
		dbURL = strings.Join(parts, " ")
	} else {
		dbURL += " host=" + hostOverride
	}

	return dbURL
}

// run is the main entry point for the cloudDNS daemon, initializing all components.
func run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 1. Initialize Structured Logging
	logLevel := slog.LevelInfo
	if lvl := os.Getenv("LOG_LEVEL"); lvl != "" {
		if err := logLevel.UnmarshalText([]byte(lvl)); err != nil {
			fmt.Fprintf(os.Stderr, "invalid LOG_LEVEL %q, defaulting to INFO\n", lvl)
		}
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var handler slog.Handler
	if os.Getenv("LOG_FORMAT") == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)

	// Add NodeID to all logs
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		h, _ := os.Hostname()
		if h != "" {
			nodeID = h
		} else {
			nodeID = "unknown-node"
		}
	}
	logger = logger.With("node_id", nodeID)

	slog.SetDefault(logger)

	dbURL := processDatabaseURL(os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_HOST"))

	if dbURL != "none" {
		parsedURL, err := url.Parse(dbURL)
		if err == nil {
			redactedURL := fmt.Sprintf("%s://%s@%s%s", parsedURL.Scheme, "***", parsedURL.Host, parsedURL.Path)
			logger.Info("database configuration", "url", redactedURL, "sslmode", parsedURL.Query().Get("sslmode"))
		} else {
			logger.Info("database configuration (DSN format)", "sslmode", "check-dsn-string")
		}
	}

	var db *sql.DB
	var repo ports.DNSRepository
	if dbURL != "none" {
		var err error
		db, err = sql.Open("pgx", dbURL)
		if err != nil {
			return err
		}
		// Pool settings configurable via env vars with sane defaults for Cloud SQL f1-micro
		maxOpenConns := 20
		if v := os.Getenv("DATABASE_MAX_OPEN_CONNS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxOpenConns = n
			}
		}
		maxIdleConns := 10
		if v := os.Getenv("DATABASE_MAX_IDLE_CONNS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				maxIdleConns = n
			}
		}
		connMaxLifetime := 5 * time.Minute
		if v := os.Getenv("DATABASE_CONN_MAX_LIFETIME_MINUTES"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				connMaxLifetime = time.Duration(n) * time.Minute
			}
		}
		db.SetMaxOpenConns(maxOpenConns)
		db.SetMaxIdleConns(maxIdleConns)
		db.SetConnMaxLifetime(connMaxLifetime)

		defer func() { _ = db.Close() }()
		repo = repository.NewPostgresRepository(db)

		// Periodic DB metrics update
		go func() {
			interval := 15 * time.Second
			if os.Getenv("TEST_MODE") == "true" {
				interval = 10 * time.Millisecond
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-ticker.C:
					stats := db.Stats()
					metrics.DBConnectionsActive.Set(float64(stats.InUse))
				}
			}
		}()

		// Periodic zone/record count metrics
		var metricsCollector *metrics.DerivedMetricCollector
		go func() {
			interval := 30 * time.Second
			if os.Getenv("TEST_MODE") == "true" {
				interval = 10 * time.Millisecond
			}
			counter := metrics.NewZoneRecordCounter(repo, interval)
			counter.Start(runCtx)
			metricsCollector = metrics.NewDerivedMetricCollector(interval)
			<-runCtx.Done()
			counter.Stop()
			metricsCollector.Stop()
		}()
	}

	var cacheInvalidator ports.CacheInvalidator
	redisURL := os.Getenv("REDIS_URL")
	var redisCache *server.RedisCache
	if redisURL != "" {
		redisPoolCfg := server.RedisPoolConfig{
			PoolSize:        100,
			MinIdleConns:    0,
			PoolTimeout:     5 * time.Minute,
			ConnMaxLifetime: 0,
		}
		if v := os.Getenv("REDIS_POOL_SIZE"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				redisPoolCfg.PoolSize = n
			} else {
				logger.Warn("invalid REDIS_POOL_SIZE, keeping default", "value", v, "reason", "must be a positive integer")
			}
		}
		if v := os.Getenv("REDIS_MIN_IDLE_CONNS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				redisPoolCfg.MinIdleConns = n
			} else {
				logger.Warn("invalid REDIS_MIN_IDLE_CONNS, keeping default", "value", v, "reason", "must be a non-negative integer")
			}
		}
		if v := os.Getenv("REDIS_POOL_TIMEOUT_MINUTES"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				redisPoolCfg.PoolTimeout = time.Duration(n) * time.Minute
			} else {
				logger.Warn("invalid REDIS_POOL_TIMEOUT_MINUTES, keeping default", "value", v, "reason", "must be a positive integer")
			}
		}
		if v := os.Getenv("REDIS_CONN_MAX_LIFETIME_MINUTES"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				redisPoolCfg.ConnMaxLifetime = time.Duration(n) * time.Minute
			} else {
				logger.Warn("invalid REDIS_CONN_MAX_LIFETIME_MINUTES, keeping default", "value", v, "reason", "must be a positive integer")
			}
		}
		redisCache = server.NewRedisCache(redisURL, "", 0, redisPoolCfg)
		// Verify connectivity
		pingCtx, cancel := context.WithTimeout(runCtx, 2*time.Second)
		if err := redisCache.Ping(pingCtx); err != nil {
			cancel()
			return fmt.Errorf("failed to connect to redis at %s: %w", redisURL, err)
		}
		cancel()
		cacheInvalidator = redisCache
		logger.Info("connected to redis cache", "url", redisURL)
	}

	dnsSvc := services.NewDNSService(repo, cacheInvalidator)

	var routingAdapter *routing.GoBGPAdapter
	var anycastMgr *services.AnycastManager

	// 2. Initialize Anycast BGP (Phase 3)
	if os.Getenv("ANYCAST_ENABLED") == "true" {
		vip := os.Getenv("ANYCAST_VIP")
		peerIP := os.Getenv("BGP_PEER_IP")

		if vip == "" || peerIP == "" {
			return fmt.Errorf("ANYCAST_VIP and BGP_PEER_IP must be set when ANYCAST_ENABLED=true")
		}

		routingAdapter = routing.NewGoBGPAdapter(logger)
		vipAdapter := routing.NewSystemVIPAdapter(logger)

		iface := os.Getenv("ANYCAST_INTERFACE")
		if iface == "" {
			iface = "lo"
		}

		localASN := getEnvUint32("ANYCAST_LOCAL_ASN", 65001)
		peerASN := getEnvUint32("BGP_PEER_ASN", 65000)

		bgpListenPort := int32(179)
		if v := os.Getenv("BGP_LISTEN_PORT"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				bgpListenPort = int32(n)
			}
		}

		// Configure RouterID and NextHop if provided
		routerID := os.Getenv("BGP_ROUTER_ID")
		nextHop := os.Getenv("BGP_NEXT_HOP")
		routingAdapter.SetConfig(routerID, bgpListenPort, nextHop)

		anycastDebounce := 5 * time.Second
		if v := os.Getenv("ANYCAST_DEBOUNCE_SECS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				anycastDebounce = time.Duration(n) * time.Second
			}
		}
		anycastMgr = services.NewAnycastManager(dnsSvc, routingAdapter, vipAdapter, vip, iface, logger, anycastDebounce)

		errChan := make(chan error, 1)
		go func() {
			if err := routingAdapter.Start(runCtx, localASN, peerASN, peerIP); err != nil {
				errChan <- fmt.Errorf("failed to start BGP speaker: %w", err)
				return
			}
			anycastMgr.Start(runCtx)
		}()

		// Provide a short grace period to immediately catch bind/startup errors
		select {
		case err := <-errChan:
			return err
		case <-time.After(500 * time.Millisecond):
			// Started successfully
		}
	}

	// 3. Start DNS Server
	dnsAddr := os.Getenv("DNS_ADDR")
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:10053"
	}
	dnsServer := server.NewServer(dnsAddr, repo, logger)
	dnsServer.Redis = redisCache

	// Configure server timeouts from env or defaults
	serverCfg := config.DefaultServerConfig()
	if v := os.Getenv("SERVER_UDP_READ_DEADLINE_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			serverCfg.UDPSocketReadDeadline = time.Duration(n) * time.Millisecond
		}
	}
	if v := os.Getenv("SERVER_SHUTDOWN_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			serverCfg.ShutdownTimeout = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("SERVER_RECURSIVE_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			serverCfg.RecursiveTimeout = time.Duration(n) * time.Second
		}
	}
	dnsServer.ServerConfig = serverCfg

	// Configure DNSSEC if trust anchors are provided
	dnsServer.DNSSECConfig = parseDNSSECConfig()

	go func() {
		if err := dnsServer.Run(runCtx); err != nil {
			logger.Error("DNS server failed", "error", err)
		}
	}()

	// 4. Start Management API
	apiAddr := os.Getenv("API_ADDR")
	if apiAddr == "" {
		apiAddr = ":8080"
	}
	apiHandler := api.New(dnsSvc, repo, logger)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)

	// For testing the full initialization path
	if apiAddr == "test-exit" {
		return nil
	}

	// 5. Start Health Monitor (Smart Engine)
	if repo != nil {
		healthMonitorOpts := &services.HealthMonitorOptions{
			HTTPTimeout: serverCfg.HealthCheckHTTPTimeout,
			TCPTimeout:  serverCfg.HealthCheckTCPTimeout,
		}
		healthMonitor := services.NewHealthMonitor(repo, logger, healthMonitorOpts)
		go healthMonitor.Start(runCtx, serverCfg.HealthCheckInterval)
	}

	logger.Info("cloudDNS services starting",
		"dns_addr", dnsAddr,
		"api_addr", apiAddr,
	)

	readHeaderTimeout := 5 * time.Second
	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	idleTimeout := 120 * time.Second
	if v := os.Getenv("API_READ_HEADER_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			readHeaderTimeout = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("API_READ_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			readTimeout = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("API_WRITE_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			writeTimeout = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("API_IDLE_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			idleTimeout = time.Duration(n) * time.Second
		}
	}

	s := &http.Server{
		Addr:              apiAddr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	certFile := os.Getenv("API_TLS_CERT")
	keyFile := os.Getenv("API_TLS_KEY")

	apiErrChan := make(chan error, 1)
	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			logger.Info("starting API server with TLS", "cert", certFile, "key", keyFile)
			err = s.ListenAndServeTLS(certFile, keyFile)
		} else {
			logger.Info("starting API server without TLS")
			err = s.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			apiErrChan <- fmt.Errorf("API server failed: %w", err)
		}
	}()

	// Wait for termination signal or API server error
	select {
	case err := <-apiErrChan:
		return err
	case <-runCtx.Done():
		logger.Info("shutting down services...")
	}

	shutdownCtx, cancel := context.WithTimeout(runCtx, 100*time.Millisecond)
	defer cancel()

	if err := s.Shutdown(shutdownCtx); err != nil {
		logger.Error("API server shutdown failed", "error", err)
	}

	if routingAdapter != nil {
		if err := routingAdapter.Stop(); err != nil {
			logger.Error("BGP speaker stop failed", "error", err)
		}
	}

	if redisCache != nil {
		errCh := make(chan error, 1)
		go func() {
			errCh <- redisCache.Close()
		}()
		select {
		case err := <-errCh:
			if err != nil {
				logger.Error("redis shutdown failed", "error", err)
			}
		case <-shutdownCtx.Done():
			logger.Warn("redis close timed out during shutdown")
		}
	}

	return nil
}

// getEnvUint32 returns an environment variable as uint32, or a default if unset/invalid.
func getEnvUint32(key string, def uint32) uint32 {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	u, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return def
	}
	return uint32(u)
}

// parseDNSSECConfig reads DNSSEC configuration from environment variables.
// TRUST_ANCHOR_<zone> contains base64-encoded DNSKEY RDATA.
// DNSSEC_MODE can be "disabled", "ad-bit-only", or "strict".
func parseDNSSECConfig() *config.DNSSECConfig {
	mode := os.Getenv("DNSSEC_MODE")
	anchors := make(map[string]string)
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "TRUST_ANCHOR_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				zone := strings.TrimPrefix(parts[0], "TRUST_ANCHOR_")
				zone = strings.ToLower(zone)
				anchors[zone] = parts[1]
			}
		}
	}
	if len(anchors) == 0 && mode == "" {
		return nil
	}
	return &config.DNSSECConfig{
		Mode:         mode,
		TrustAnchors: anchors,
	}
}
