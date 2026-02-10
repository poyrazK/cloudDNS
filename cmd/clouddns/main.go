package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
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

	// Listen on 10053 for development (since 53 requires root)
	srv := server.NewServer("127.0.0.1:10053", repo)
	if err := srv.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
