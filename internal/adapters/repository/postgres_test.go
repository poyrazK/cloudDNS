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

	// 1. Test Ping
	if err := repo.Ping(ctx); err != nil {
		t.Errorf("Ping failed: %v", err)
	}

	// 2. Test CreateZone
	zoneID1 := "550e8400-e29b-41d4-a716-446655440000"
	zone := &domain.Zone{ID: zoneID1, Name: "base.test.", TenantID: "t1"}
	if err := repo.CreateZone(ctx, zone); err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}

	// 3. Test GetZone
	gotZone, err := repo.GetZone(ctx, "base.test.")
	if err != nil || gotZone == nil || gotZone.ID != zoneID1 {
		t.Errorf("GetZone failed: %v, got %+v", err, gotZone)
	}

	// 4. Test CreateRecord
	recordID1 := "550e8400-e29b-41d4-a716-446655440001"
	record := &domain.Record{
		ID: recordID1, ZoneID: zoneID1, Name: "www.base.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300,
	}
	if err := repo.CreateRecord(ctx, record); err != nil {
		t.Fatalf("CreateRecord failed: %v", err)
	}

	// 5. Test GetRecords (Case Insensitive)
	recs, err := repo.GetRecords(ctx, "WwW.BaSe.TeSt.", domain.TypeA, "8.8.8.8")
	if err != nil || len(recs) != 1 {
		t.Errorf("GetRecords failed: %v, count: %d", err, len(recs))
	}

	// 6. Test GetIPsForName
	ips, err := repo.GetIPsForName(ctx, "www.base.test.", "8.8.8.8")
	if err != nil || len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("GetIPsForName failed: %v, got %v", err, ips)
	}

	// 7. Test ListRecordsForZone
	allRecs, err := repo.ListRecordsForZone(ctx, zoneID1)
	if err != nil || len(allRecs) != 1 {
		t.Errorf("ListRecordsForZone failed: %v, count: %d", err, len(allRecs))
	}

	// 8. Test Audit Logs
	auditID1 := "550e8400-e29b-41d4-a716-446655440002"
	audit := &domain.AuditLog{
		ID: auditID1, TenantID: "t1", Action: "CREATE", ResourceType: "ZONE", ResourceID: zoneID1, Details: "...", CreatedAt: time.Now(),
	}
	repo.SaveAuditLog(ctx, audit)
	logs, _ := repo.GetAuditLogs(ctx, "t1")
	if len(logs) != 1 {
		t.Errorf("Audit logs expected 1, got %d", len(logs))
	}

	// 9. Test DeleteRecord
	if err := repo.DeleteRecord(ctx, recordID1, zoneID1); err != nil {
		t.Errorf("DeleteRecord failed: %v", err)
	}

	// 10. Test DeleteZone
	if err := repo.DeleteZone(ctx, zoneID1, "t1"); err != nil {
		t.Errorf("DeleteZone failed: %v", err)
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
