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
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	// 1. Test GetRecords
	t.Run("GetRecords", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "network"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, nil, nil)

		mock.ExpectQuery(`SELECT (.+) FROM dns_records WHERE LOWER\(name\) = LOWER\(\$1\) AND \(network IS NULL OR \$2::inet <<= network\) AND type = \$3`).
			WithArgs("www.test.", "8.8.8.8", "A").
			WillReturnRows(rows)

		recs, err := repo.GetRecords(ctx, "www.test.", domain.TypeA, "8.8.8.8")
		if err != nil {
			t.Errorf("GetRecords failed: %v", err)
		}
		if len(recs) != 1 || recs[0].Content != "1.2.3.4" {
			t.Errorf("Unexpected records: %+v", recs)
		}
	})

	// 2. Test GetZone
	t.Run("GetZone", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "created_at", "updated_at"}).
			AddRow("z1", "t1", "test.com.", "", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT (.+) FROM dns_zones WHERE LOWER\(name\) = LOWER\(\$1\)`).
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
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "network"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, 10, nil)

		mock.ExpectQuery(`SELECT (.+) FROM dns_records WHERE zone_id = \$1`).
			WithArgs("z1").
			WillReturnRows(rows)

		recs, err := repo.ListRecordsForZone(ctx, "z1")
		if err != nil {
			t.Errorf("ListRecordsForZone failed: %v", err)
		}
		if len(recs) != 1 || *recs[0].Priority != 10 {
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
		rec := &domain.Record{ID: "r2", ZoneID: "z1", Name: "new.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 60}
		mock.ExpectExec(`INSERT INTO dns_records`).
			WithArgs(rec.ID, rec.ZoneID, rec.Name, rec.Type, rec.Content, rec.TTL, rec.Priority, rec.Network, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.CreateRecord(ctx, rec)
		if err != nil {
			t.Errorf("CreateRecord failed: %v", err)
		}
	})

	// 7. Test ListZones (with and without tenantID)
	t.Run("ListZones", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "created_at", "updated_at"}).
			AddRow("z1", "t1", "test.com.", "", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT (.+) FROM dns_zones WHERE tenant_id = \$1`).
			WithArgs("t1").
			WillReturnRows(rows)

		zones, err := repo.ListZones(ctx, "t1")
		if err != nil || len(zones) != 1 {
			t.Errorf("ListZones with tenant failed: %v", err)
		}

		mock.ExpectQuery(`SELECT (.+) FROM dns_zones`).
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
			WithArgs(change.ID, change.ZoneID, change.Serial, change.Action, change.Name, string(change.Type), change.Content, change.TTL, change.Priority, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := repo.RecordZoneChange(ctx, change)
		if err != nil {
			t.Errorf("RecordZoneChange failed: %v", err)
		}
	})

	// 9. Test ListZoneChanges
	t.Run("ListZoneChanges", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "zone_id", "serial", "action", "name", "type", "content", "ttl", "priority", "created_at"}).
			AddRow("c1", "z1", 1, "ADD", "test.", "A", "1.1.1.1", 60, nil, time.Now())

		mock.ExpectQuery(`SELECT (.+) FROM dns_zone_changes WHERE zone_id = \$1 AND serial > \$2`).
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

		mock.ExpectQuery(`SELECT (.+) FROM audit_logs WHERE tenant_id = \$1`).
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

		mock.ExpectQuery(`SELECT (.+) FROM dnssec_keys WHERE zone_id = \$1`).
			WithArgs("z1").
			WillReturnRows(sqlmock.NewRows([]string{"id", "zone_id", "key_type", "algorithm", "private_key", "public_key", "active", "created_at", "updated_at"}).
				AddRow("k1", "z1", "ZSK", 13, []byte{}, []byte{}, true, time.Now(), time.Now()))

		keys, err := repo.ListKeysForZone(ctx, "z1")
		if err != nil || len(keys) != 1 {
			t.Errorf("ListKeysForZone failed: %v", err)
		}

		mock.ExpectExec(`UPDATE dnssec_keys SET active = \$1`).
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

	// 13. Remaining methods
	t.Run("OtherMethods", func(t *testing.T) {
		// GetIPsForName
		mock.ExpectQuery(`SELECT content FROM dns_records`).WithArgs("www.test.", "1.1.1.1").
			WillReturnRows(sqlmock.NewRows([]string{"content"}).AddRow("1.2.3.4"))
		ips, _ := repo.GetIPsForName(ctx, "www.test.", "1.1.1.1")
		if len(ips) != 1 { t.Errorf("GetIPsForName failed") }

		// DeleteRecord
		mock.ExpectExec(`DELETE FROM dns_records WHERE id = \$1 AND zone_id = \$2`).WithArgs("r1", "z1").
			WillReturnResult(sqlmock.NewResult(0, 1))
		repo.DeleteRecord(ctx, "r1", "z1")

		// DeleteRecordsByNameAndType
		mock.ExpectExec(`DELETE FROM dns_records WHERE zone_id = \$1 AND LOWER\(name\) = LOWER\(\$2\) AND type = \$3`).WithArgs("z1", "test.", "A").
			WillReturnResult(sqlmock.NewResult(0, 1))
		repo.DeleteRecordsByNameAndType(ctx, "z1", "test.", "A")

		// DeleteRecordsByName
		mock.ExpectExec(`DELETE FROM dns_records WHERE zone_id = \$1 AND LOWER\(name\) = LOWER\(\$2\)`).WithArgs("z1", "test.").
			WillReturnResult(sqlmock.NewResult(0, 1))
		repo.DeleteRecordsByName(ctx, "z1", "test.")

		// DeleteRecordSpecific
		mock.ExpectExec(`DELETE FROM dns_records WHERE zone_id = \$1 AND LOWER\(name\) = LOWER\(\$2\) AND type = \$3 AND content = \$4`).WithArgs("z1", "test.", "A", "1.1.1.1").
			WillReturnResult(sqlmock.NewResult(0, 1))
		repo.DeleteRecordSpecific(ctx, "z1", "test.", "A", "1.1.1.1")

		// Ping
		mock.ExpectPing()
		repo.Ping(ctx)
	})

	// 14. Error Paths
	t.Run("ErrorPaths", func(t *testing.T) {
		dbErr := errors.New("db error")
		
		// GetRecords Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.GetRecords(ctx, "", "", "")

		// GetIPsForName Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.GetIPsForName(ctx, "", "")

		// GetZone Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.GetZone(ctx, "")

		// ListRecordsForZone Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.ListRecordsForZone(ctx, "")

		// ListZones Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.ListZones(ctx, "")

		// ListZoneChanges Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.ListZoneChanges(ctx, "", 0)

		// GetAuditLogs Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.GetAuditLogs(ctx, "")

		// ListKeysForZone Error
		mock.ExpectQuery(`SELECT`).WillReturnError(dbErr)
		repo.ListKeysForZone(ctx, "")

		// rows.Scan failure in ListZones
		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123)) // Should be string
		repo.ListZones(ctx, "")

		// rows.Scan failure in GetRecords
		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "network"}).
			AddRow(1, 2, 3, 4, 5, 6, 7, 8))
		repo.GetRecords(ctx, "test", "A", "")

		// rows.Scan failure in ListRecordsForZone
		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "network"}).
			AddRow(1, 2, 3, 4, 5, 6, 7, 8))
		repo.ListRecordsForZone(ctx, "z1")

		// rows.Scan failure in GetIPsForName
		mock.ExpectQuery(`SELECT content FROM dns_records`).WillReturnRows(sqlmock.NewRows([]string{"content"}).AddRow(123))
		repo.GetIPsForName(ctx, "test", "")

		// rows.Scan failure in ListZoneChanges
		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "zone_id", "serial", "action", "name", "type", "content", "ttl", "priority", "created_at"}).
			AddRow(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
		repo.ListZoneChanges(ctx, "z1", 0)

		// rows.Scan failure in GetAuditLogs
		mock.ExpectQuery(`SELECT`).WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "action", "resource_type", "resource_id", "details", "created_at"}).
			AddRow(1, 2, 3, 4, 5, 6, 7))
		repo.GetAuditLogs(ctx, "t1")

		// CreateZoneWithRecords Transaction Begin Error
		mock.ExpectBegin().WillReturnError(dbErr)
		repo.CreateZoneWithRecords(ctx, &domain.Zone{}, nil)
	})
}
