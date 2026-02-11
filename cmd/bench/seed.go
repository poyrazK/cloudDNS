package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var tlds = []string{"com", "net", "org", "io", "dev", "ai", "cloud", "gov", "edu", "tr", "com.tr", "me", "info"}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:password@localhost:5432/clouddns?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	zoneID := uuid.New()
	
	fmt.Println("Preparing 10,000,000 record environment...")
	
	// Create zone if not exists
	_, err = db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", zoneID, "bench", "root")
	if err != nil {
		log.Fatalf("failed to create zone: %v", err)
	}

	total := 10000000
	batchSize := 5000 // Increased batch size for better performance
	
	fmt.Printf("Seeding 10,000,000 Realistic Records...\n")

	for i := 0; i < total; i += batchSize {
		valueStrings := make([]string, 0, batchSize)
		valueArgs := make([]interface{}, 0, batchSize*6)
		
		for j := 0; j < batchSize; j++ {
			idx := i + j
			if idx >= total {
				break
			}
			offset := len(valueArgs)
			
			// Realistic domain pattern: host-[number].[tld]
			name := fmt.Sprintf("host-%d.%s", idx, tlds[idx%len(tlds)])
			
			valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)", offset+1, offset+2, offset+3, offset+4, offset+5, offset+6))
			valueArgs = append(valueArgs, uuid.New(), zoneID, name, "A", "1.2.3.4", 3600)
		}

		if len(valueStrings) == 0 {
			break
		}

		query := fmt.Sprintf("INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES %s", strings.Join(valueStrings, ","))
		_, err := db.ExecContext(ctx, query, valueArgs...)
		if err != nil {
			log.Fatalf("Batch failed at %d: %v", i, err)
		}

		if i%100000 == 0 {
			fmt.Printf("Progress: %d/%d (%.1f%%)\n", i, total, float64(i)/float64(total)*100)
		}
	}

	fmt.Println("10,000,000 Records Seeded Successfully.")
}
