package main

import (
	"database/sql"
	"fmt"
	"log"
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
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Fallback for development, though we should prefer env vars
		dbURL = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fmt.Printf("Warning: Could not ping database: %v\n", err)
	}

	repo := repository.NewPostgresRepository(db)
	dnsSvc := services.NewDNSService(repo)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Start DNS Server
	// Listen on 10053 for development (since 53 requires root)
	dnsServer := server.NewServer("127.0.0.1:10053", repo, logger)
	go func() {
		if err := dnsServer.Run(); err != nil {
			log.Fatalf("DNS Server failed: %v", err)
		}
	}()

	// Start Management API
	apiHandler := api.NewAPIHandler(dnsSvc)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)

	fmt.Println("Management API listening on :8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("HTTP Server failed: %v", err)
	}
}
