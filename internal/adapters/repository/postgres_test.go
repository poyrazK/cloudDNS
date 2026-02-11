package repository

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	ctx := context.Background()

	// Start Postgres Container
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("clouddns_test"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("5432").
				WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		t.Fatalf("failed to start container: %s", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %s", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open db: %s", err)
	}

	// Load Schema
	schemaPath := filepath.Join(".", "schema.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read schema: %s", err)
	}

	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("failed to apply schema: %s", err)
	}

	return db, func() {
		db.Close()
		pgContainer.Terminate(ctx)
	}
}

func TestPostgresRepository_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	// 1. Test CreateZoneWithRecords
	zoneID := "550e8400-e29b-41d4-a716-446655440000"
	zone := &domain.Zone{
		ID:       zoneID,
		TenantID: "tenant-1",
		Name:     "example.com.",
	}
	records := []domain.Record{
		{
			ID:      "550e8400-e29b-41d4-a716-446655440001",
			ZoneID:  zoneID,
			Name:    "example.com.",
			Type:    domain.TypeA,
			Content: "1.2.3.4",
			TTL:     3600,
		},
	}

	err := repo.CreateZoneWithRecords(ctx, zone, records)
	if err != nil {
		t.Fatalf("CreateZoneWithRecords failed: %v", err)
	}

	// 2. Test GetRecords (Global)
	found, err := repo.GetRecords(ctx, "example.com.", domain.TypeA, "8.8.8.8")
	if err != nil || len(found) != 1 {
		t.Errorf("Expected 1 global record, got %d", len(found))
	}

	// 3. Test Split-Horizon (Network specific)
	internalNet := "10.0.0.0/8"
	repo.CreateRecord(ctx, &domain.Record{
		ID:      "550e8400-e29b-41d4-a716-446655440002",
		ZoneID:  zoneID,
		Name:    "example.com.",
		Type:    domain.TypeA,
		Content: "10.0.0.5",
		TTL:     60,
		Network: &internalNet,
	})

	// Query from public IP -> should get only global (1.2.3.4)
	publicRes, _ := repo.GetRecords(ctx, "example.com.", domain.TypeA, "8.8.8.8")
	if len(publicRes) != 1 || publicRes[0].Content != "1.2.3.4" {
		t.Errorf("Public client got wrong records: %v", publicRes)
	}

	// Query from internal IP -> should get both global AND internal (if logic allows) 
	// or prioritized. Our current SQL matches both if network is NULL or matches.
	internalRes, _ := repo.GetRecords(ctx, "example.com.", domain.TypeA, "10.5.5.5")
	if len(internalRes) != 2 {
		t.Errorf("Internal client expected 2 records, got %d", len(internalRes))
	}

	// 4. Test ListZones
	zones, err := repo.ListZones(ctx, "tenant-1")
	if err != nil || len(zones) != 1 {
		t.Errorf("ListZones failed: %v, count: %d", err, len(zones))
	}

	// 5. Test Audit Logs
	audit := &domain.AuditLog{
		ID:           "550e8400-e29b-41d4-a716-446655440003",
		TenantID:     "tenant-1",
		Action:       "CREATE_ZONE",
		ResourceType: "ZONE",
		ResourceID:   zoneID,
		Details:      "Test log",
		CreatedAt:    time.Now(),
	}
	err = repo.SaveAuditLog(ctx, audit)
	if err != nil {
		t.Errorf("SaveAuditLog failed: %v", err)
	}

	logs, err := repo.GetAuditLogs(ctx, "tenant-1")
	if err != nil || len(logs) != 1 {
		t.Errorf("GetAuditLogs failed: %v, count: %d", err, len(logs))
	}

	// 6. Test Delete
	err = repo.DeleteZone(ctx, zoneID, "tenant-1")
	if err != nil {
		t.Errorf("DeleteZone failed: %v", err)
	}

	// Verify cascade delete of records
	leftover, _ := repo.GetRecords(ctx, "example.com.", domain.TypeA, "8.8.8.8")
	if len(leftover) != 0 {
		t.Errorf("Records were not deleted after zone deletion")
	}
}
