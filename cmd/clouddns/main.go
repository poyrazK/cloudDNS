package main

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/api"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
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
	defer db.Close()

	repo := repository.NewPostgresRepository(db)
	dnsSvc := services.NewDNSService(repo)

	// 2. Start DNS Server
	dnsAddr := os.Getenv("DNS_ADDR")
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:10053"
	}
	dnsServer := server.NewServer(dnsAddr, repo, logger)
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
	)

	// For testing the full initialization path
	if apiAddr == "test-exit" {
		return nil
	}

	return http.ListenAndServe(apiAddr, mux)
}
