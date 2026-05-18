// iana-import fetches the root zone file from IANA and imports
// DNS records into the cloudDNS database.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
)

const rootZoneURL = "https://www.internic.net/domain/root.zone"

func main() {
	if err := Run(os.Args); err != nil {
		slog.Error("iana-import failed", "error", err)
		os.Exit(1)
	}
}

func Run([]string) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		if errClose := db.Close(); errClose != nil {
			slog.Error("failed to close database", "error", errClose)
		}
	}()

	if errPing := db.Ping(); errPing != nil {
		return fmt.Errorf("failed to validate database connection: %w", errPing)
	}

	repo := repository.NewPostgresRepository(db)
	return RunImport(context.Background(), repo, rootZoneURL)
}

func RunImport(ctx context.Context, repo ports.DNSRepository, url string) error {
	fmt.Printf("Downloading IANA root zone from %s...\n", url)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			slog.Error("failed to close response body", "error", errClose)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	parser := master.New()
	parser.Origin = "."

	fmt.Println("Parsing root zone file...")
	data, err := parser.Parse(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse: %w", err)
	}

	fmt.Printf("Parsed %d records. Importing into database...\n", len(data.Records))

	// 1. Ensure root zone exists
	zone, err := repo.GetZone(ctx, ".")
	if err != nil {
		return fmt.Errorf("failed to check for root zone: %w", err)
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
			return fmt.Errorf("failed to create root zone: %w", err)
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
			return fmt.Errorf("failed to import batch %d-%d: %w", i, end, err)
		}

		totalImported += len(batch)
		fmt.Printf("Progress: %d/%d records imported...\n", totalImported, len(data.Records))
	}

	fmt.Printf("\nImport Completed Successfully!\n")
	fmt.Printf("Total Records: %d\n", totalImported)
	fmt.Printf("Time Taken:    %v\n", time.Since(start))
	return nil
}
