package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Create a test zone
	zoneID := uuid.New()
	_, err = db.ExecContext(ctx, `
		INSERT INTO dns_zones (id, tenant_id, name, description)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO NOTHING`,
		zoneID, "benchmark-tenant", "test.com", "Benchmark Test Zone")
	if err != nil {
		log.Fatalf("failed to create zone: %v", err)
	}

	fmt.Println("Seeding 10,000 records into test.com...")

	// 2. Batch insert records
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatalf("failed to begin tx: %v", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO dns_records (id, zone_id, name, type, content, ttl)
		VALUES ($1, $2, $3, $4, $5, $6)`)
	if err != nil {
		log.Fatalf("failed to prepare stmt: %v", err)
	}
	defer stmt.Close()

	for i := 0; i < 10000; i++ {
		name := fmt.Sprintf("req-%d.test.com", i)
		_, err = stmt.ExecContext(ctx, uuid.New(), zoneID, name, "A", "1.2.3.4", 3600)
		if err != nil {
			log.Fatalf("failed to insert record %d: %v", i, err)
		}
		if i%1000 == 0 {
			fmt.Printf("Inserted %d records...\n", i)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("failed to commit tx: %v", err)
	}

	fmt.Println("Seeding complete. 10,000 records ready for benchmark.")
}
