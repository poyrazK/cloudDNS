package repository

import (
	"context"
	"database/sql"
	"net"
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

	// 10. Test DeleteRecordsByNameAndType
	rid2 := "550e8400-e29b-41d4-a716-446655440003"
	repo.CreateRecord(ctx, &domain.Record{ID: rid2, ZoneID: zoneID1, Name: "del.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60})
	if err := repo.DeleteRecordsByNameAndType(ctx, zoneID1, "del.test.", domain.TypeA); err != nil {
		t.Errorf("DeleteRecordsByNameAndType failed: %v", err)
	}

	// 11. Test DeleteRecordsByName
	rid3 := "550e8400-e29b-41d4-a716-446655440004"
	repo.CreateRecord(ctx, &domain.Record{ID: rid3, ZoneID: zoneID1, Name: "delname.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60})
	if err := repo.DeleteRecordsByName(ctx, zoneID1, "delname.test."); err != nil {
		t.Errorf("DeleteRecordsByName failed: %v", err)
	}

	// 12. Test DeleteRecordSpecific
	rid4 := "550e8400-e29b-41d4-a716-446655440005"
	repo.CreateRecord(ctx, &domain.Record{ID: rid4, ZoneID: zoneID1, Name: "specific.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60})
	if err := repo.DeleteRecordSpecific(ctx, zoneID1, "specific.test.", domain.TypeA, "1.1.1.1"); err != nil {
		t.Errorf("DeleteRecordSpecific failed: %v", err)
	}

	// 13. Test Zone Changes (IXFR)
	changeID1 := "550e8400-e29b-41d4-a716-446655440006"
	change := &domain.ZoneChange{
		ID: changeID1, ZoneID: zoneID1, Serial: 100, Action: "ADD", Name: "new.test.", Type: domain.TypeA, Content: "4.4.4.4", TTL: 300, CreatedAt: time.Now(),
	}
	if err := repo.RecordZoneChange(ctx, change); err != nil {
		t.Errorf("RecordZoneChange failed: %v", err)
	}
	changes, _ := repo.ListZoneChanges(ctx, zoneID1, 99)
	if len(changes) != 1 || changes[0].ID != changeID1 {
		t.Errorf("ListZoneChanges expected 1 change, got %d", len(changes))
	}

	// 14. Test Split-Horizon (Network Matching)
	rid5 := "550e8400-e29b-41d4-a716-446655440007"
	netStr := "192.168.1.0/24"
	repo.CreateRecord(ctx, &domain.Record{ID: rid5, ZoneID: zoneID1, Name: "private.test.", Type: domain.TypeA, Content: "10.0.0.1", TTL: 60, Network: &netStr})
	
	// Should match from 192.168.1.50
	recs, _ = repo.GetRecords(ctx, "private.test.", domain.TypeA, "192.168.1.50")
	if len(recs) != 1 {
		t.Errorf("Split-Horizon match failed")
	}
	// Should NOT match from 8.8.8.8
	recs, _ = repo.GetRecords(ctx, "private.test.", domain.TypeA, "8.8.8.8")
	if len(recs) != 0 {
		t.Errorf("Split-Horizon isolation failed")
	}

	// 15. Test DeleteZone
	if err := repo.DeleteZone(ctx, zoneID1, "t1"); err != nil {
		t.Errorf("DeleteZone failed: %v", err)
	}
}

func TestConvertPacketRecordToDomain(t *testing.T) {
	zoneID := "550e8400-e29b-41d4-a716-446655440008"
	pRec := packet.DnsRecord{
		Name: "conv.test.",
		Type: packet.A,
		TTL:  300,
		IP:   net.ParseIP("1.2.3.4"),
	}
	
	dRec, err := ConvertPacketRecordToDomain(pRec, zoneID)
	if err != nil {
		t.Fatalf("ConvertPacketRecordToDomain failed: %v", err)
	}
	if dRec.Content != "1.2.3.4" || dRec.Type != domain.TypeA {
		t.Errorf("Conversion mismatch: %+v", dRec)
	}

	// SOA
	pSOA := packet.DnsRecord{
		Name: "soa.test.",
		Type: packet.SOA,
		TTL: 3600,
		MName: "ns1.", RName: "admin.", Serial: 1, Refresh: 2, Retry: 3, Expire: 4, Minimum: 5,
	}
	dSOA, _ := ConvertPacketRecordToDomain(pSOA, zoneID)
	if dSOA.Type != domain.TypeSOA {
		t.Errorf("SOA conversion type mismatch")
	}
}

func TestPostgresRepository_EdgeCases(t *testing.T) {
	if testing.Short() { t.Skip() }
	db, cleanup := setupTestDB(t)
	defer cleanup()
	repo := NewPostgresRepository(db)
	ctx := context.Background()

	// 1. Test CreateZoneWithRecords
	zID := "550e8400-e29b-41d4-a716-446655440009"
	zone := &domain.Zone{ID: zID, Name: "batch.test.", TenantID: "t1"}
	recs := []domain.Record{
		{ID: "550e8400-e29b-41d4-a716-446655440010", ZoneID: zID, Name: "batch.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60},
	}
	if err := repo.CreateZoneWithRecords(ctx, zone, recs); err != nil {
		t.Errorf("CreateZoneWithRecords failed: %v", err)
	}

	// 2. Test GetZone No Rows
	z, err := repo.GetZone(ctx, "missing.zone.")
	if err != nil || z != nil {
		t.Errorf("Expected nil for missing zone, got %v", z)
	}

	// 3. Test GetRecords with empty type
	all, _ := repo.GetRecords(ctx, "batch.test.", "", "127.0.0.1")
	if len(all) == 0 {
		t.Errorf("Expected records for empty type query")
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
