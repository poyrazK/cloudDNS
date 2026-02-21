package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/api"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/adapters/routing"
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

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	// For testing purposes, if DB is "none", we just exit early with success
	if dbURL == "none" {
		return nil
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return err
	}

	repo := repository.NewPostgresRepository(db)

	var redisCache *server.RedisCache
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		// NewRedisCache(addr, password, db)
		redisCache = server.NewRedisCache(redisURL, "", 0)
		logger.Info("connected to redis cache", "url", redisURL)
	}

	dnsSvc := services.NewDNSService(repo, redisCache)

	// 2. Initialize Anycast BGP (Phase 3)
	if os.Getenv("ANYCAST_ENABLED") == "true" {
		routingAdapter := routing.NewGoBGPAdapter(logger)
		vipAdapter := routing.NewSystemVIPAdapter(logger)
		
		vip := os.Getenv("ANYCAST_VIP")
		iface := os.Getenv("ANYCAST_INTERFACE")
		if iface == "" {
			iface = "lo"
		}
		
		localASN := uint32(65001) // Default
		peerASN := uint32(65000)  // Default
		peerIP := os.Getenv("BGP_PEER_IP")
		
		anycastMgr := services.NewAnycastManager(dnsSvc, routingAdapter, vipAdapter, vip, iface, logger)
		
		go func() {
			ctx := context.Background()
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

	// 3. Start Management API
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
	if apiAddr == "test-exit" {
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

	return s.ListenAndServe()
}
