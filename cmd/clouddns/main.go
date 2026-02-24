package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/api"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/adapters/routing"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("application failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Initialize Structured Logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	var db *sql.DB
	var repo ports.DNSRepository
	if dbURL != "none" {
		var err error
		db, err = sql.Open("pgx", dbURL)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		repo = repository.NewPostgresRepository(db)
	}

	var cacheInvalidator ports.CacheInvalidator
	redisURL := os.Getenv("REDIS_URL")
	var redisCache *server.RedisCache
	if redisURL != "" {
		redisCache = server.NewRedisCache(redisURL, "", 0)
		// Verify connectivity
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
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
		
		// Configure RouterID and NextHop if provided
		routerID := os.Getenv("BGP_ROUTER_ID")
		nextHop := os.Getenv("BGP_NEXT_HOP")
		routingAdapter.SetConfig(routerID, 179, nextHop)

		anycastMgr = services.NewAnycastManager(dnsSvc, routingAdapter, vipAdapter, vip, iface, logger)
		
		go func() {
			if err := routingAdapter.Start(ctx, localASN, peerASN, peerIP); err != nil {
				logger.Error("failed to start BGP speaker", "error", err)
				return
			}
			anycastMgr.Start(ctx)
		}()
	}

	// 3. Start DNS Server
	dnsAddr := os.Getenv("DNS_ADDR")
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:10053"
	}
	dnsServer := server.NewServer(dnsAddr, repo, logger)
	dnsServer.Redis = redisCache

	go func() {
		if err := dnsServer.Run(); err != nil {
			logger.Error("DNS server failed", "error", err)
		}
	}()

	// 4. Start Management API
	apiAddr := os.Getenv("API_ADDR")
	if apiAddr == "" {
		apiAddr = ":8080"
	}
	apiHandler := api.NewAPIHandler(dnsSvc)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)

	logger.Info("cloudDNS services starting", 
		"dns_addr", dnsAddr, 
		"api_addr", apiAddr,
		"node_id", dnsServer.NodeID,
	)

	// For testing the full initialization path
	if apiAddr == "test-exit" || dbURL == "none" {
		return nil
	}

	s := &http.Server{
		Addr:              apiAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("API server failed", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down services...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond) // Fast timeout for tests
	defer cancel()

	if err := s.Shutdown(shutdownCtx); err != nil {
		logger.Error("API server shutdown failed", "error", err)
	}

	if routingAdapter != nil {
		if err := routingAdapter.Stop(); err != nil {
			logger.Error("BGP speaker stop failed", "error", err)
		}
	}

	return nil
}

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
