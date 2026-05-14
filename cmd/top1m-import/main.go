// top1m-import imports the Cisco Umbrella Top 1M DNS dataset into cloudDNS.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
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
		slog.Error("failed to connect to database", "error", err); os.Exit(1)
	}
	defer func() {
		if errClose := db.Close(); errClose != nil {
			slog.Error("failed to close database", "error", errClose)
		}
	}()

	fmt.Printf("Downloading Top 1M list from %s...\n", top1mURL)
	resp, err := http.Get(top1mURL)
	if err != nil {
		slog.Error("failed to download", "error", err); os.Exit(1)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			slog.Error("failed to close response body", "error", errClose)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		slog.Error("bad status", "status", resp.Status); os.Exit(1)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("failed to read body", "error", err); os.Exit(1)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		slog.Error("failed to open zip", "error", err); os.Exit(1)
	}

	if len(zr.File) == 0 {
		slog.Error("zip file is empty"); os.Exit(1)
	}

	f, err := zr.File[0].Open()
	if err != nil {
		slog.Error("failed to open csv in zip", "error", err); os.Exit(1)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			slog.Error("failed to close file in zip", "error", errClose)
		}
	}()

	reader := csv.NewReader(f)
	repo := repository.NewPostgresRepository(db)
	ctx := context.Background()

	// Ensure top1m zone exists
	zoneName := "top1m.test."
	zone, err := repo.GetZone(ctx, zoneName)
	if err != nil {
		slog.Error("failed to check zone", "error", err); os.Exit(1)
	}

	var zoneID string
	if zone == nil {
		zoneID = uuid.New().String()
		err = repo.CreateZone(ctx, &domain.Zone{
			ID: zoneID, TenantID: "bench", Name: zoneName,
		})
		if err != nil {
			slog.Error("failed to create zone", "error", err); os.Exit(1)
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
				slog.Error("batch insert failed", "error", err); os.Exit(1)
			}
			total += len(records)
			fmt.Printf("Imported %d records...\n", total)
			records = records[:0]
		}
	}

	if len(records) > 0 {
		if err := repo.BatchCreateRecords(ctx, records); err != nil {
			slog.Error("final batch insert failed", "error", err); os.Exit(1)
		}
		total += len(records)
	}

	fmt.Printf("\nSuccess! Imported %d real-world domains in %v\n", total, time.Since(start))
}
