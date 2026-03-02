package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestPostgresRepository_Unit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %s", err)
	}
	defer func() { _ = db.Close() }()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	// 1. Test GetRecords
	t.Run("GetRecords", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, nil, nil, nil, nil, "HTTP", "http://target", "HEALTHY")

		// Anchored query with WHERE predicates
		mock.ExpectQuery(`SELECT .* FROM dns_records r .* WHERE LOWER\(r\.name\) = LOWER\(\$1\) AND \(r\.network IS NULL OR \$2::inet <<= r\.network\)`).
			WithArgs("www.test.", "8.8.8.8", "A").
			WillReturnRows(rows)

		recs, err := repo.GetRecords(ctx, "www.test.", domain.TypeA, "8.8.8.8")
		if err != nil {
			t.Errorf("GetRecords failed: %v", err)
		}
		if len(recs) != 1 || recs[0].Content != "1.2.3.4" || recs[0].HealthStatus != "HEALTHY" {
			t.Errorf("Unexpected records: %+v", recs)
		}
	})

	// 2. Test GetZone
	t.Run("GetZone", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "created_at", "updated_at"}).
			AddRow("z1", "t1", "test.com.", "", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE LOWER\(name\) = LOWER\(\$1\)`).
			WithArgs("test.com.").
			WillReturnRows(rows)

		zone, err := repo.GetZone(ctx, "test.com.")
		if err != nil {
			t.Errorf("GetZone failed: %v", err)
		}
		if zone == nil || zone.ID != "z1" {
			t.Errorf("Unexpected zone: %+v", zone)
		}
	})

	// 3. Test CreateZone
	t.Run("CreateZone", func(t *testing.T) {
		zone := &domain.Zone{ID: "z2", Name: "new.test.", TenantID: "t1"}
		mock.ExpectExec(`INSERT INTO dns_zones`).
			WithArgs(zone.ID, zone.TenantID, zone.Name, zone.VPCID, zone.Description, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateZone(ctx, zone)
		if err != nil {
			t.Errorf("CreateZone failed: %v", err)
		}
	})

	// 4. Test ListRecordsForZone
	t.Run("ListRecordsForZone", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "hc_type", "hc_target", "h_status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, 10, 5, 80, nil, "NONE", nil, "UNKNOWN")

		mock.ExpectQuery(`SELECT .* FROM dns_records r .* WHERE r\.zone_id = \$1 AND z\.tenant_id = \$2`).
			WithArgs("z1", "").
			WillReturnRows(rows)

		recs, err := repo.ListRecordsForZone(ctx, "z1", "")
		if err != nil {
			t.Errorf("ListRecordsForZone failed: %v", err)
		}
		if len(recs) != 1 || *recs[0].Priority != 10 || *recs[0].Weight != 5 || *recs[0].Port != 80 {
			t.Errorf("Unexpected records: %+v", recs)
		}
	})

	// 5. Test DeleteZone
	t.Run("DeleteZone", func(t *testing.T) {
		mock.ExpectExec(`DELETE FROM dns_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("z1", "t1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := repo.DeleteZone(ctx, "z1", "t1")
		if err != nil {
			t.Errorf("DeleteZone failed: %v", err)
		}
	})

	// 6. Test CreateRecord
	t.Run("CreateRecord", func(t *testing.T) {
		rec := &domain.Record{ID: "r2", ZoneID: "z1", Name: "new.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60, HealthCheckType: domain.HealthCheckHTTP, HealthCheckTarget: "http://t"}
		mock.ExpectExec(`INSERT INTO dns_records`).
			WithArgs(rec.ID, rec.ZoneID, rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, rec.Weight, rec.Port, rec.Network, string(rec.HealthCheckType), rec.HealthCheckTarget, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateRecord(ctx, rec)
		if err != nil {
			t.Errorf("CreateRecord failed: %v", err)
		}
	})

	// 7. Test ListZones
	t.Run("ListZones", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "created_at", "updated_at"}).
			AddRow("z1", "t1", "test.com.", "", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE tenant_id = \$1`).
			WithArgs("t1").
			WillReturnRows(rows)

		zones, err := repo.ListZones(ctx, "t1")
		if err != nil || len(zones) != 1 {
			t.Errorf("ListZones with tenant failed: %v", err)
		}

		mock.ExpectQuery(`SELECT .* FROM dns_zones`).
			WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "created_at", "updated_at"}).
				AddRow("z1", "t1", "test.com.", "", "", time.Now(), time.Now()))

		zones, err = repo.ListZones(ctx, "")
		if err != nil || len(zones) != 1 {
			t.Errorf("ListZones without tenant failed: %v", err)
		}
	})

	// 8. Test RecordZoneChange
	t.Run("RecordZoneChange", func(t *testing.T) {
		change := &domain.ZoneChange{ID: "c1", ZoneID: "z1", Serial: 1, Action: "ADD", Name: "test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60, CreatedAt: time.Now()}
		mock.ExpectExec(`INSERT INTO dns_zone_changes`).
			WithArgs(change.ID, change.ZoneID, change.Serial, change.Action, change.Name, string(change.Type), change.Content, change.TTL, change.Priority, change.Weight, change.Port, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.RecordZoneChange(ctx, change)
		if err != nil {
			t.Errorf("RecordZoneChange failed: %v", err)
		}
	})

	// 9. Test ListZoneChanges
	t.Run("ListZoneChanges", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "zone_id", "serial", "action", "name", "type", "content", "ttl", "priority", "weight", "port", "created_at"}).
			AddRow("c1", "z1", 1, "ADD", "test.", "A", "1.1.1.1", 60, nil, nil, nil, time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zone_changes WHERE zone_id = \$1 AND serial > \$2 ORDER BY serial ASC, created_at ASC`).
			WithArgs("z1", 0).
			WillReturnRows(rows)

		changes, err := repo.ListZoneChanges(ctx, "z1", 0)
		if err != nil || len(changes) != 1 {
			t.Errorf("ListZoneChanges failed: %v", err)
		}
	})

	// 10. Test Audit Logs
	t.Run("AuditLogs", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO audit_logs`).
			WithArgs("a1", "t1", "ACT", "RES", "rid", "det", sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.SaveAuditLog(ctx, &domain.AuditLog{ID: "a1", TenantID: "t1", Action: "ACT", ResourceType: "RES", ResourceID: "rid", Details: "det", CreatedAt: time.Now()})
		if err != nil {
			t.Errorf("SaveAuditLog failed: %v", err)
		}

		mock.ExpectQuery(`SELECT .* FROM audit_logs WHERE tenant_id = \$1 ORDER BY created_at DESC`).
			WithArgs("t1").
			WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "action", "resource_type", "resource_id", "details", "created_at"}).
				AddRow("a1", "t1", "ACT", "RES", "rid", "det", time.Now()))

		logs, err := repo.GetAuditLogs(ctx, "t1")
		if err != nil || len(logs) != 1 {
			t.Errorf("GetAuditLogs failed: %v", err)
		}
	})

	// 11. Test DNSSEC Keys
	t.Run("DNSSECKeys", func(t *testing.T) {
		key := &domain.DNSSECKey{ID: "k1", ZoneID: "z1", KeyType: "ZSK", Algorithm: 13, Active: true}
		mock.ExpectExec(`INSERT INTO dnssec_keys`).
			WithArgs(key.ID, key.ZoneID, key.KeyType, key.Algorithm, key.PrivateKey, key.PublicKey, key.Active, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateKey(ctx, key)
		if err != nil {
			t.Errorf("CreateKey failed: %v", err)
		}

		mock.ExpectQuery(`SELECT .* FROM dnssec_keys WHERE zone_id = \$1`).
			WithArgs("z1").
			WillReturnRows(sqlmock.NewRows([]string{"id", "zone_id", "key_type", "algorithm", "private_key", "public_key", "active", "created_at", "updated_at"}).
				AddRow("k1", "z1", "ZSK", 13, []byte{}, []byte{}, true, time.Now(), time.Now()))

		keys, err := repo.ListKeysForZone(ctx, "z1")
		if err != nil || len(keys) != 1 {
			t.Errorf("ListKeysForZone failed: %v", err)
		}

		mock.ExpectExec(`UPDATE dnssec_keys SET active = \$1, updated_at = \$2 WHERE id = \$3`).
			WithArgs(false, sqlmock.AnyArg(), "k1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err = repo.UpdateKey(ctx, &domain.DNSSECKey{ID: "k1", Active: false, UpdatedAt: time.Now()})
		if err != nil {
			t.Errorf("UpdateKey failed: %v", err)
		}
	})

	// 12. Test CreateZoneWithRecords
	t.Run("CreateZoneWithRecords", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectExec(`INSERT INTO dns_zones`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec(`INSERT INTO dns_records`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		zone := &domain.Zone{ID: "z3", Name: "batch.test."}
		recs := []domain.Record{{ID: "r3", ZoneID: "z3", Name: "r3.test.", Type: "A", Content: "1.1.1.1"}}
		err := repo.CreateZoneWithRecords(ctx, zone, recs)
		if err != nil {
			t.Errorf("CreateZoneWithRecords failed: %v", err)
		}
	})

	// 13. Test Smart Engine GSLB methods
	t.Run("SmartEngineMethods", func(t *testing.T) {
		// UpdateRecordHealth
		mock.ExpectExec(`INSERT INTO record_health`).
			WithArgs("r1", "HEALTHY", "none").
			WillReturnResult(sqlmock.NewResult(1, 1))
		err := repo.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "none")
		if err != nil {
			t.Errorf("UpdateRecordHealth failed: %v", err)
		}

		// GetRecordsToProbe
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, nil, nil, nil, nil, "HTTP", "http://target")
		mock.ExpectQuery(`SELECT .* FROM dns_records WHERE health_check_type IN \('HTTP', 'TCP'\) AND health_check_target IS NOT NULL AND health_check_target <> ''`).
			WillReturnRows(rows)

		recs, err := repo.GetRecordsToProbe(ctx)
		if err != nil || len(recs) != 1 {
			t.Errorf("GetRecordsToProbe failed: %v", err)
		}
	})

	// 14. Remaining methods
	t.Run("OtherMethods", func(t *testing.T) {
		// GetIPsForName
		mock.ExpectQuery(`SELECT content FROM dns_records WHERE LOWER\(name\) = LOWER\(\$1\) AND type = 'A' AND \(network IS NULL OR \$2::inet <<= network\)`).WithArgs("www.test.", "1.1.1.1").
			WillReturnRows(sqlmock.NewRows([]string{"content"}).AddRow("1.2.3.4"))
		ips, err := repo.GetIPsForName(ctx, "www.test.", "1.1.1.1")
		if err != nil || len(ips) != 1 {
			t.Errorf("GetIPsForName failed")
		}

		// DeleteRecord
		mock.ExpectExec(`DELETE FROM dns_records WHERE id = \$1 AND zone_id = \$2 AND EXISTS .*`).WithArgs("r1", "z1", "").
			WillReturnResult(sqlmock.NewResult(0, 1))
		err = repo.DeleteRecord(ctx, "r1", "z1", "")
		if err != nil {
			t.Errorf("DeleteRecord failed: %v", err)
		}

		// Ping
		mock.ExpectPing()
		err = repo.Ping(ctx)
		if err != nil {
			t.Errorf("Ping failed: %v", err)
		}
	})

	// 15. Error Paths
	t.Run("ErrorPaths", func(t *testing.T) {
		dbErr := errors.New("db error")

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.GetRecords(ctx, "", "", ""); err == nil {
			t.Errorf("Expected error in GetRecords")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.GetIPsForName(ctx, "", ""); err == nil {
			t.Errorf("Expected error in GetIPsForName")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.GetZone(ctx, ""); err == nil {
			t.Errorf("Expected error in GetZone")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.ListRecordsForZone(ctx, "", ""); err == nil {
			t.Errorf("Expected error in ListRecordsForZone")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.ListZones(ctx, ""); err == nil {
			t.Errorf("Expected error in ListZones")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.ListZoneChanges(ctx, "", 0); err == nil {
			t.Errorf("Expected error in ListZoneChanges")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.GetAuditLogs(ctx, ""); err == nil {
			t.Errorf("Expected error in GetAuditLogs")
		}

		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		if _, err := repo.ListKeysForZone(ctx, ""); err == nil {
			t.Errorf("Expected error in ListKeysForZone")
		}

		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))
		if _, err := repo.ListZones(ctx, ""); err == nil {
			t.Errorf("Expected Scan error in ListZones")
		}

		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))
		if _, err := repo.GetRecords(ctx, "test", "A", ""); err == nil {
			t.Errorf("Expected Scan error in GetRecords")
		}

		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))
		if _, err := repo.ListRecordsForZone(ctx, "z1", ""); err == nil {
			t.Errorf("Expected Scan error in ListRecordsForZone")
		}

		mock.ExpectQuery(`SELECT content FROM dns_records .*`).WillReturnRows(sqlmock.NewRows([]string{"content"}).AddRow(time.Now()))
		if _, err := repo.GetIPsForName(ctx, "test", ""); err == nil {
			t.Errorf("Expected Scan error in GetIPsForName")
		}

		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))
		if _, err := repo.ListZoneChanges(ctx, "z1", 0); err == nil {
			t.Errorf("Expected Scan error in ListZoneChanges")
		}

		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))
		if _, err := repo.GetAuditLogs(ctx, "t1"); err == nil {
			t.Errorf("Expected Scan error in GetAuditLogs")
		}

		mock.ExpectBegin().WillReturnError(dbErr)
		if err := repo.CreateZoneWithRecords(ctx, &domain.Zone{}, nil); err == nil {
			t.Errorf("Expected Begin error in CreateZoneWithRecords")
		}
	})
}
