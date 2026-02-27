package repository

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	testDB           *sql.DB
	containerOnce    sync.Once
	containerErr     error
	containerCleanup func()
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	containerOnce.Do(func() {
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
			containerErr = err
			return
		}

		connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			containerErr = err
			return
		}

		db, err := sql.Open("pgx", connStr)
		if err != nil {
			containerErr = err
			return
		}

		schemaPath := filepath.Join(".", "schema.sql")
		schema, err := os.ReadFile(schemaPath) // #nosec G304
		if err != nil {
			containerErr = err
			return
		}

		if _, err := db.Exec(string(schema)); err != nil {
			containerErr = err
			return
		}

		testDB = db
		containerCleanup = func() {
			_ = db.Close()
			_ = pgContainer.Terminate(ctx)
		}
	})

	if containerErr != nil {
		t.Fatalf("failed to setup global test container: %v", containerErr)
	}

	return testDB, func() {
		// We don't terminate the global container here,
		// just clean up data if needed. For now, we trust tests to be clean.
		_, _ = testDB.Exec("TRUNCATE dns_records, dns_zones, audit_logs, zone_changes CASCADE")
	}
}

func TestPostgresRepositoryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	const (
		tIPv41     = "1.2.3.4"
		tDNS8      = "8.8.8.8"
		tIPv4Local = "1.1.1.1"
		tPrivate   = "private.test."
		tBatch     = "batch.test."
	)

	// Check if Docker is available
	if !dockerAvailable() {
		t.Skip("Docker not available, skipping integration test")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	// 1. Test Ping
	if errPing := repo.Ping(ctx); errPing != nil {
		t.Errorf("Ping failed: %v", errPing)
	}

	// 2. Test CreateZone
	zoneID1 := "550e8400-e29b-41d4-a716-446655440000"
	zone := &domain.Zone{ID: zoneID1, Name: "base.test.", TenantID: "t1"}
	if errCreate := repo.CreateZone(ctx, zone); errCreate != nil {
		t.Fatalf("CreateZone failed: %v", errCreate)
	}

	// 3. Test GetZone
	gotZone, errGet := repo.GetZone(ctx, "base.test.")
	if errGet != nil || gotZone == nil || gotZone.ID != zoneID1 {
		t.Errorf("GetZone failed: %v, got %+v", errGet, gotZone)
	}

	// 4. Test CreateRecord
	recordID1 := "550e8400-e29b-41d4-a716-446655440001"
	record := &domain.Record{
		ID: recordID1, ZoneID: zoneID1, Name: "www.base.test.", Type: domain.TypeA, Content: tIPv41, TTL: 300,
	}
	if errRec := repo.CreateRecord(ctx, record); errRec != nil {
		t.Fatalf("CreateRecord failed: %v", errRec)
	}

	// 4.1 Test GetRecord
	gotRec, errGetRec := repo.GetRecord(ctx, recordID1, zoneID1)
	if errGetRec != nil || gotRec == nil || gotRec.ID != recordID1 {
		t.Errorf("GetRecord failed: %v, got %+v", errGetRec, gotRec)
	}

	// 5. Test GetRecords (Case Insensitive)
	recs, errRecs := repo.GetRecords(ctx, "WwW.BaSe.TeSt.", domain.TypeA, tDNS8)
	if errRecs != nil || len(recs) != 1 {
		t.Errorf("GetRecords failed: %v, count: %d", errRecs, len(recs))
	}

	// 6. Test GetIPsForName
	ips, errIPs := repo.GetIPsForName(ctx, "www.base.test.", tDNS8)
	if errIPs != nil || len(ips) != 1 || ips[0] != tIPv41 {
		t.Errorf("GetIPsForName failed: %v, got %v", errIPs, ips)
	}

	// 7. Test ListRecordsForZone
	allRecs, errList := repo.ListRecordsForZone(ctx, zoneID1)
	if errList != nil || len(allRecs) != 1 {
		t.Errorf("ListRecordsForZone failed: %v, count: %d", errList, len(allRecs))
	}

	// 8. Test Audit Logs
	auditID1 := "550e8400-e29b-41d4-a716-446655440002"
	audit := &domain.AuditLog{
		ID: auditID1, TenantID: "t1", Action: "CREATE", ResourceType: "ZONE", ResourceID: zoneID1, Details: "...", CreatedAt: time.Now(),
	}
	_ = repo.SaveAuditLog(ctx, audit)
	logs, errAudit := repo.GetAuditLogs(ctx, "t1")
	if errAudit != nil {
		t.Errorf("GetAuditLogs failed: %v", errAudit)
	}
	if len(logs) != 1 {
		t.Errorf("Audit logs expected 1, got %d", len(logs))
	}

	// 9. Test DeleteRecord
	if errDel := repo.DeleteRecord(ctx, recordID1, zoneID1); errDel != nil {
		t.Errorf("DeleteRecord failed: %v", errDel)
	}

	// 10. Test DeleteRecordsByNameAndType
	rid2 := "550e8400-e29b-41d4-a716-446655440003"
	_ = repo.CreateRecord(ctx, &domain.Record{ID: rid2, ZoneID: zoneID1, Name: "del.test.", Type: domain.TypeA, Content: tIPv4Local, TTL: 60})
	if errDelNT := repo.DeleteRecordsByNameAndType(ctx, zoneID1, "del.test.", domain.TypeA); errDelNT != nil {
		t.Errorf("DeleteRecordsByNameAndType failed: %v", errDelNT)
	}

	// 11. Test DeleteRecordsByName
	rid3 := "550e8400-e29b-41d4-a716-446655440004"
	_ = repo.CreateRecord(ctx, &domain.Record{ID: rid3, ZoneID: zoneID1, Name: "delname.test.", Type: domain.TypeA, Content: tIPv4Local, TTL: 60})
	if errDelN := repo.DeleteRecordsByName(ctx, zoneID1, "delname.test."); errDelN != nil {
		t.Errorf("DeleteRecordsByName failed: %v", errDelN)
	}

	// 12. Test DeleteRecordSpecific
	rid4 := "550e8400-e29b-41d4-a716-446655440005"
	_ = repo.CreateRecord(ctx, &domain.Record{ID: rid4, ZoneID: zoneID1, Name: "specific.test.", Type: domain.TypeA, Content: tIPv4Local, TTL: 60})
	if errDelS := repo.DeleteRecordSpecific(ctx, zoneID1, "specific.test.", domain.TypeA, tIPv4Local); errDelS != nil {
		t.Errorf("DeleteRecordSpecific failed: %v", errDelS)
	}

	// 13. Test Zone Changes (IXFR)
	changeID1 := "550e8400-e29b-41d4-a716-446655440006"
	change := &domain.ZoneChange{
		ID: changeID1, ZoneID: zoneID1, Serial: 100, Action: "ADD", Name: "new.test.", Type: domain.TypeA, Content: "4.4.4.4", TTL: 300, CreatedAt: time.Now(),
	}
	if errChg := repo.RecordZoneChange(ctx, change); errChg != nil {
		t.Errorf("RecordZoneChange failed: %v", errChg)
	}
	changes, errListChg := repo.ListZoneChanges(ctx, zoneID1, 99)
	if errListChg != nil {
		t.Errorf("ListZoneChanges failed: %v", errListChg)
	}
	if len(changes) != 1 || changes[0].ID != changeID1 {
		t.Errorf("ListZoneChanges expected 1 change, got %d", len(changes))
	}

	// 14. Test Split-Horizon (Network Matching)
	rid5 := "550e8400-e29b-41d4-a716-446655440007"
	netStr := "192.168.1.0/24"
	_ = repo.CreateRecord(ctx, &domain.Record{ID: rid5, ZoneID: zoneID1, Name: tPrivate, Type: domain.TypeA, Content: "10.0.0.1", TTL: 60, Network: &netStr})

	// Should match from 192.168.1.50
	recs, errPriv := repo.GetRecords(ctx, tPrivate, domain.TypeA, "192.168.1.50")
	if errPriv != nil {
		t.Errorf("GetRecords failed: %v", errPriv)
	}
	if len(recs) != 1 {
		t.Errorf("Split-Horizon match failed")
	}
	// Should NOT match from 8.8.8.8
	recs, errPub := repo.GetRecords(ctx, tPrivate, domain.TypeA, tDNS8)
	if errPub != nil {
		t.Errorf("GetRecords failed: %v", errPub)
	}
	if len(recs) != 0 {
		t.Errorf("Split-Horizon isolation failed")
	}

	// 15. Test BatchCreateRecords
	ridBatch1 := "550e8400-e29b-41d4-a716-446655440011"
	ridBatch2 := "550e8400-e29b-41d4-a716-446655440012"
	batchRecs := []domain.Record{
		{ID: ridBatch1, ZoneID: zoneID1, Name: "b1.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60},
		{ID: ridBatch2, ZoneID: zoneID1, Name: "b2.test.", Type: domain.TypeA, Content: "2.2.2.2", TTL: 60},
	}
	if errBatch := repo.BatchCreateRecords(ctx, batchRecs); errBatch != nil {
		t.Errorf("BatchCreateRecords failed: %v", errBatch)
	}

	// 16. Test DeleteZone
	if errDelZone := repo.DeleteZone(ctx, zoneID1, "t1"); errDelZone != nil {
		t.Errorf("DeleteZone failed: %v", errDelZone)
	}
}

func TestPostgresRepositoryAPIKeys(t *testing.T) {
	if testing.Short() || !dockerAvailable() {
		t.Skip("skipping integration test")
	}

	db, cleanup := setupTestDB(t)
	defer cleanup()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	const (
		tKeyID    = "550e8400-e29b-41d4-a716-446655440008"
		tKeyHash  = "hash-123"
		tTenantID = "tenant-1"
	)

	// 1. Create API Key
	apiKey := &domain.APIKey{
		ID:        tKeyID,
		TenantID:  tTenantID,
		Name:      "Test Key",
		KeyHash:   tKeyHash,
		KeyPrefix: "cdns_123",
		Role:      domain.RoleAdmin,
		Active:    true,
		CreatedAt: time.Now(),
	}
	if err := repo.CreateAPIKey(ctx, apiKey); err != nil {
		t.Fatalf("CreateAPIKey failed: %v", err)
	}

	// 2. Get API Key by Hash
	got, err := repo.GetAPIKeyByHash(ctx, tKeyHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByHash failed: %v", err)
	}
	if got == nil || got.ID != tKeyID {
		t.Errorf("Expected %s, got %+v", tKeyID, got)
	}

	// 3. List API Keys
	keys, err := repo.ListAPIKeys(ctx, tTenantID)
	if err != nil {
		t.Fatalf("ListAPIKeys failed: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != tKeyID {
		t.Errorf("Expected 1 key (%s), got %d keys", tKeyID, len(keys))
	}

	// 4. Delete API Key
	if err := repo.DeleteAPIKey(ctx, tKeyID); err != nil {
		t.Fatalf("DeleteAPIKey failed: %v", err)
	}

	// 5. Verify Deletion
	gotAfter, errAfter := repo.GetAPIKeyByHash(ctx, tKeyHash)
	if errAfter != nil {
		t.Fatalf("GetAPIKeyByHash after delete failed: %v", errAfter)
	}
	if gotAfter != nil {
		t.Errorf("Expected nil after deletion, got %+v", gotAfter)
	}
}

func dockerAvailable() bool {
	if os.Getenv("DOCKER_HOST") != "" {
		return true
	}
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}

func TestPostgresRepositoryEdgeCases(t *testing.T) {
	if testing.Short() || !dockerAvailable() {
		t.Skip("skipping edge case test")
	}
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
	if errCreateZR := repo.CreateZoneWithRecords(ctx, zone, recs); errCreateZR != nil {
		t.Errorf("CreateZoneWithRecords failed: %v", errCreateZR)
	}

	// 2. Test GetZone No Rows
	z, errGZ := repo.GetZone(ctx, "missing.zone.")
	if errGZ != nil || z != nil {
		t.Errorf("Expected nil for missing zone, got %v", z)
	}

	// 3. Test GetRecords with empty type
	all, _ := repo.GetRecords(ctx, "batch.test.", "", "127.0.0.1")
	if len(all) == 0 {
		t.Errorf("Expected records for empty type query")
	}
}
