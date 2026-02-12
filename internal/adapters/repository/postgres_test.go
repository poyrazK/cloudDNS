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
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	ctx := context.Background()

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

	// 2. Test Case-Insensitive Lookup (RFC 1034)
	found, err := repo.GetRecords(ctx, "ExAmPlE.CoM.", domain.TypeA, "8.8.8.8")
	if err != nil || len(found) != 1 {
		t.Errorf("Expected 1 record via mixed-case lookup, got %d", len(found))
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

	publicRes, _ := repo.GetRecords(ctx, "example.com.", domain.TypeA, "8.8.8.8")
	if len(publicRes) != 1 || publicRes[0].Content != "1.2.3.4" {
		t.Errorf("Public client got wrong records: %v", publicRes)
	}

	internalRes, _ := repo.GetRecords(ctx, "example.com.", domain.TypeA, "10.5.5.5")
	if len(internalRes) != 2 {
		t.Errorf("Internal client expected 2 records, got %d", len(internalRes))
	}

	// 4. Test ListRecordsForZone (AXFR)
	allRecords, err := repo.ListRecordsForZone(ctx, zoneID)
	if err != nil || len(allRecords) < 1 {
		t.Errorf("ListRecordsForZone failed: %v", err)
	}

	// 5. Test ListZones
	zones, err := repo.ListZones(ctx, "tenant-1")
	if err != nil || len(zones) != 1 {
		t.Errorf("ListZones failed: %v, count: %d", err, len(zones))
	}

	// 6. Test Audit Logs
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

	// 7. Test Delete
	err = repo.DeleteZone(ctx, zoneID, "tenant-1")
	if err != nil {
		t.Errorf("DeleteZone failed: %v", err)
	}

	leftover, _ := repo.GetRecords(ctx, "example.com.", domain.TypeA, "8.8.8.8")
	if len(leftover) != 0 {
		t.Errorf("Records were not deleted after zone deletion")
	}
}

func TestConvertDomainToPacketRecord(t *testing.T) {
	tests := []struct {
		name    string
		input   domain.Record
		want    packet.QueryType
		content string
	}{
		{
			name: "A record",
			input: domain.Record{Name: "test.com", Type: domain.TypeA, Content: "1.2.3.4"},
			want: packet.A,
		},
		{
			name: "PTR record",
			input: domain.Record{Name: "1.0.0.127.in-addr.arpa", Type: domain.TypePTR, Content: "localhost"},
			want: packet.PTR,
		},
		{
			name: "SOA record",
			input: domain.Record{Name: "example.com", Type: domain.TypeSOA, Content: "ns1.example.com admin.example.com 1 2 3 4 5"},
			want: packet.SOA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertDomainToPacketRecord(tt.input)
			if err != nil {
				t.Fatalf("ConvertDomainToPacketRecord() error = %v", err)
			}
			if got.Type != tt.want {
				t.Errorf("Got type %v, want %v", got.Type, tt.want)
			}
			if got.Name != tt.input.Name+"." {
				t.Errorf("Got name %s, want %s", got.Name, tt.input.Name+".")
			}
		})
	}
}
