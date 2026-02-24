package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
)

const rootZoneURL = "https://www.internic.net/domain/root.zone"

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

	repo := repository.NewPostgresRepository(db)

	fmt.Printf("Downloading IANA root zone from %s...\n", rootZoneURL)
	resp, err := http.Get(rootZoneURL)
	if err != nil {
		log.Fatalf("failed to download root zone: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("bad status: %s", resp.Status)
	}

	parser := master.NewMasterParser()
	parser.Origin = "."
	
	fmt.Println("Parsing root zone file...")
	data, err := parser.Parse(resp.Body)
	if err != nil {
		log.Fatalf("failed to parse root zone: %v", err)
	}

	fmt.Printf("Parsed %d records. Importing into database...\n", len(data.Records))

	ctx := context.Background()
	
	// 1. Ensure root zone exists
	zone, err := repo.GetZone(ctx, ".")
	if err != nil {
		log.Fatalf("failed to check for root zone: %v", err)
	}

	var zoneID string
	if zone == nil {
		zoneID = uuid.New().String()
		newZone := &domain.Zone{
			ID:        zoneID,
			TenantID:  "iana",
			Name:      ".",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := repo.CreateZone(ctx, newZone); err != nil {
			log.Fatalf("failed to create root zone: %v", err)
		}
		fmt.Println("Created new root zone (.)")
	} else {
		zoneID = zone.ID
		fmt.Printf("Using existing root zone (.) ID: %s\n", zoneID)
	}

	// 2. Batch Import Records
	start := time.Now()
	batchSize := 1000
	totalImported := 0

	for i := 0; i < len(data.Records); i += batchSize {
		end := i + batchSize
		if end > len(data.Records) {
			end = len(data.Records)
		}

		batch := data.Records[i:end]
		for j := range batch {
			batch[j].ID = uuid.New().String()
			batch[j].ZoneID = zoneID
			batch[j].CreatedAt = time.Now()
			batch[j].UpdatedAt = time.Now()
			
			// Standardize name
			if !strings.HasSuffix(batch[j].Name, ".") {
				batch[j].Name += "."
			}
		}

		if err := repo.BatchCreateRecords(ctx, batch); err != nil {
			log.Fatalf("failed to import batch %d-%d: %v", i, end, err)
		}

		totalImported += len(batch)
		fmt.Printf("Progress: %d/%d records imported...\n", totalImported, len(data.Records))
	}

	fmt.Printf("\nImport Completed Successfully!\n")
	fmt.Printf("Total Records: %d\n", totalImported)
	fmt.Printf("Time Taken:    %v\n", time.Since(start))
}
