package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

const top1mURL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer func() {
		if errClose := db.Close(); errClose != nil {
			log.Printf("failed to close database: %v", errClose)
		}
	}()

	fmt.Printf("Downloading Top 1M list from %s...\n", top1mURL)
	resp, err := http.Get(top1mURL)
	if err != nil {
		log.Fatalf("failed to download: %v", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Printf("failed to close response body: %v", errClose)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("bad status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read body: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		log.Fatalf("failed to open zip: %v", err)
	}

	if len(zr.File) == 0 {
		log.Fatal("zip file is empty")
	}

	f, err := zr.File[0].Open()
	if err != nil {
		log.Fatalf("failed to open csv in zip: %v", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Printf("failed to close file in zip: %v", errClose)
		}
	}()

	reader := csv.NewReader(f)
	repo := repository.NewPostgresRepository(db)
	ctx := context.Background()

	// Ensure top1m zone exists
	zoneName := "top1m.test."
	zone, err := repo.GetZone(ctx, zoneName)
	if err != nil {
		log.Fatalf("failed to check zone: %v", err)
	}

	var zoneID string
	if zone == nil {
		zoneID = uuid.New().String()
		err = repo.CreateZone(ctx, &domain.Zone{
			ID: zoneID, TenantID: "bench", Name: zoneName,
		})
		if err != nil {
			log.Fatalf("failed to create zone: %v", err)
		}
	} else {
		zoneID = zone.ID
	}

	fmt.Println("Starting batch import...")
	batchSize := 5000
	records := make([]domain.Record, 0, batchSize)
	total := 0
	start := time.Now()

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(line) < 2 {
			continue
		}

		domainName := line[1]
		if !strings.HasSuffix(domainName, ".") {
			domainName += "."
		}

		records = append(records, domain.Record{
			ID:        uuid.New().String(),
			ZoneID:    zoneID,
			Name:      domainName,
			Type:      domain.TypeA,
			Content:   "1.2.3.4",
			TTL:       3600,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		})

		if len(records) >= batchSize {
			if err := repo.BatchCreateRecords(ctx, records); err != nil {
				log.Fatalf("batch insert failed: %v", err)
			}
			total += len(records)
			fmt.Printf("Imported %d records...\n", total)
			records = records[:0]
		}
	}

	if len(records) > 0 {
		if err := repo.BatchCreateRecords(ctx, records); err != nil {
			log.Fatalf("final batch insert failed: %v", err)
		}
		total += len(records)
	}

	fmt.Printf("\nSuccess! Imported %d real-world domains in %v\n", total, time.Since(start))
}
