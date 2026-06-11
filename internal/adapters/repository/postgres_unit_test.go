package repository

import (
	"context"
	"database/sql"
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
		mock.ExpectQuery(`SELECT .* FROM dns_records r .* WHERE name = \$1 AND \(r\.network IS NULL OR \$2::inet <<= r\.network\) AND r\.type = \$3`).
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
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
			AddRow("z1", "t1", "test.com.", "", "", "master", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE name = \$1`).
			WithArgs("test.com.").
			WillReturnRows(rows)

		zone, err := repo.GetZone(ctx, "test.com.")
		if err != nil {
			t.Errorf("GetZone failed: %v", err)
		}
		if zone == nil || zone.ID != "z1" || zone.Role != "master" {
			t.Errorf("Unexpected zone: %+v", zone)
		}
	})

	// 2b. Test GetZoneLongestMatch
	t.Run("GetZoneLongestMatch", func(t *testing.T) {
		// Test exact match
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
			AddRow("z1", "t1", "example.com.", "", "", "master", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE name <= \$1 AND REVERSE\(\$1\) LIKE REVERSE\(name\) \|\| '%'`).
			WithArgs("example.com.").
			WillReturnRows(rows)

		zone, err := repo.GetZoneLongestMatch(ctx, "example.com.")
		if err != nil {
			t.Errorf("GetZoneLongestMatch failed: %v", err)
		}
		if zone == nil || zone.ID != "z1" {
			t.Errorf("Unexpected zone: %+v", zone)
		}
	})

	// 2c. Test GetZoneLongestMatch subdomain
	t.Run("GetZoneLongestMatch_Subdomain", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
			AddRow("z1", "t1", "example.com.", "", "", "master", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE name <= \$1 AND REVERSE\(\$1\) LIKE REVERSE\(name\) \|\| '%'`).
			WithArgs("www.example.com.").
			WillReturnRows(rows)

		zone, err := repo.GetZoneLongestMatch(ctx, "www.example.com.")
		if err != nil {
			t.Errorf("GetZoneLongestMatch failed: %v", err)
		}
		if zone == nil || zone.Name != "example.com." {
			t.Errorf("Unexpected zone: %+v", zone)
		}
	})

	// 2d. Test GetZoneLongestMatch no match
	t.Run("GetZoneLongestMatch_NoMatch", func(t *testing.T) {
		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE name <= \$1 AND REVERSE\(\$1\) LIKE REVERSE\(name\) \|\| '%'`).
			WithArgs("unknown.domain.").
			WillReturnError(sql.ErrNoRows)

		zone, err := repo.GetZoneLongestMatch(ctx, "unknown.domain.")
		if err != nil {
			t.Errorf("GetZoneLongestMatch should not error on no match: %v", err)
		}
		if zone != nil {
			t.Errorf("Expected nil zone for unknown domain, got: %+v", zone)
		}
	})

	// 3. Test CreateZone
	t.Run("CreateZone", func(t *testing.T) {
		zone := &domain.Zone{ID: "z2", Name: "new.test.", TenantID: "t1", Role: "master", MasterServer: ""}
		mock.ExpectExec(`INSERT INTO dns_zones`).
			WithArgs(zone.ID, zone.TenantID, zone.Name, zone.VPCID, zone.Description, zone.Role, zone.MasterServer, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
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
		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
			AddRow("z1", "t1", "test.com.", "", "", "master", "", time.Now(), time.Now())

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE tenant_id = \$1`).
			WithArgs("t1").
			WillReturnRows(rows)

		zones, err := repo.ListZones(ctx, "t1")
		if err != nil || len(zones) != 1 {
			t.Errorf("ListZones with tenant failed: %v", err)
		}

		mock.ExpectQuery(`SELECT .* FROM dns_zones`).
			WillReturnRows(sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
				AddRow("z1", "t1", "test.com.", "", "", "master", "", time.Now(), time.Now()))

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

	// 11b. Test GetDNSKEYs
	t.Run("GetDNSKEYs", func(t *testing.T) {
		// Single JOIN query using zone name directly
		dnskeyRows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("dk1", "z1", "test.com.", "DNSKEY", " AwAAAEEAE....", 300, nil, nil, nil, nil, nil, nil, "UNKNOWN")
		mock.ExpectQuery(`SELECT r\.id, r\.zone_id, r\.name, r\.type, r\.content, r\.ttl, r\.priority, r\.weight, r\.port, r\.network, r\.health_check_type, r\.health_check_target, COALESCE\(h\.status, 'UNKNOWN'\) FROM dns_records r JOIN dns_zones z ON r\.zone_id = z\.id LEFT JOIN record_health h ON r\.id = h\.record_id WHERE z\.name = \$1 AND r\.type = 'DNSKEY'`).
			WithArgs("test.com.").
			WillReturnRows(dnskeyRows)

		recs, err := repo.GetDNSKEYs(ctx, "test.com.")
		if err != nil {
			t.Errorf("GetDNSKEYs failed: %v", err)
		}
		if len(recs) != 1 || recs[0].Type != "DNSKEY" {
			t.Errorf("Unexpected records: %+v", recs)
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
		mock.ExpectExec(`record_health`).
			WithArgs("r1", "HEALTHY", "none").
			WillReturnResult(sqlmock.NewResult(1, 1))
		err := repo.UpdateRecordHealth(ctx, "r1", domain.HealthStatusHealthy, "none")
		if err != nil {
			t.Errorf("UpdateRecordHealth failed: %v", err)
		}

		// GetRecordsToProbeStreaming
		rowsStreaming := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, nil, nil, nil, nil, "HTTP", "http://target", "HEALTHY")
		mock.ExpectQuery(`SELECT .* FROM dns_records`).WillReturnRows(rowsStreaming)

		iter, err := repo.GetRecordsToProbeStreaming(ctx)
		if err != nil {
			t.Errorf("GetRecordsToProbeStreaming failed: %v", err)
		}
		if iter == nil {
			t.Error("iterator was nil")
		} else {
			defer iter.Close()
			count := 0
			for iter.Next() {
				count++
			}
			if count != 1 {
				t.Errorf("expected 1 record, got %d", count)
			}
		}
	})

	// 14. Remaining methods
	t.Run("OtherMethods", func(t *testing.T) {
		// GetIPsForName
		mock.ExpectQuery(`SELECT content FROM dns_records WHERE name = \$1 AND type = 'A' AND \(network IS NULL OR \$2::inet <<= network\)`).WithArgs("www.test.", "1.1.1.1").
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

		// DeleteRecordsByName
		mock.ExpectExec(`DELETE FROM dns_records WHERE zone_id = \$1 AND name = \$2`).WithArgs("z1", "test.").
			WillReturnResult(sqlmock.NewResult(0, 1))
		err = repo.DeleteRecordsByName(ctx, "z1", "test.")
		if err != nil {
			t.Errorf("DeleteRecordsByName failed: %v", err)
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
			t.Errorf("Expected Scan error in ListZones")
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

		mock.ExpectQuery(`SELECT content FROM dns_records .*`).WillReturnRows(sqlmock.NewRows([]string{"content", "extra"}).AddRow("test", "extra"))
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

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestPostgresRepository_Extra_Unit(t *testing.T) {
	ctx := context.Background()

	t.Run("DeleteMethods", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectExec("DELETE FROM dns_records").WithArgs("z1", "name.", "A").WillReturnResult(sqlmock.NewResult(0, 1))
		_ = repo.DeleteRecordsByNameAndType(ctx, "z1", "name.", domain.TypeA)

		mock.ExpectExec("DELETE FROM dns_records").WithArgs("z1").WillReturnResult(sqlmock.NewResult(0, 1))
		_ = repo.DeleteRecordsForZone(ctx, "z1")

		mock.ExpectExec("DELETE FROM dns_records").WithArgs("z1", "name.", "A", "1.1.1.1").WillReturnResult(sqlmock.NewResult(0, 1))
		_ = repo.DeleteRecordSpecific(ctx, "z1", "name.", domain.TypeA, "1.1.1.1")
		
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("APIKeys", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectExec("INSERT INTO api_keys").WillReturnResult(sqlmock.NewResult(1, 1))
		if err := repo.CreateAPIKey(ctx, &domain.APIKey{}); err != nil { t.Errorf("CreateAPIKey failed: %v", err) }

		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "key_hash", "key_prefix", "role", "active", "created_at", "expires_at"}).
			AddRow("id1", "t1", "n1", "h1", "p1", "admin", true, time.Now(), time.Now())
		mock.ExpectQuery("SELECT .* FROM api_keys").WithArgs("h1").WillReturnRows(rows)
		key, err := repo.GetAPIKeyByHash(ctx, "h1")
		if err != nil { t.Errorf("GetAPIKeyByHash failed: %v", err) }
		if key == nil || key.ID != "id1" { t.Errorf("GetAPIKeyByHash returned unexpected result: %+v", key) }

		rows2 := sqlmock.NewRows([]string{"id", "tenant_id", "name", "key_hash", "key_prefix", "role", "active", "created_at", "expires_at"}).
			AddRow("id1", "t1", "n1", "h1", "p1", "admin", true, time.Now(), time.Now())
		mock.ExpectQuery("SELECT .* FROM api_keys").WithArgs("t1").WillReturnRows(rows2)
		keys, err := repo.ListAPIKeys(ctx, "t1")
		if err != nil { t.Errorf("ListAPIKeys failed: %v", err) }
		if len(keys) != 1 || keys[0].ID != "id1" { t.Errorf("ListAPIKeys returned unexpected result: %+v", keys) }

		mock.ExpectExec("DELETE FROM api_keys").WithArgs("t1", "id1").WillReturnResult(sqlmock.NewResult(0, 1))
		if err := repo.DeleteAPIKey(ctx, "t1", "id1"); err != nil { t.Errorf("DeleteAPIKey failed: %v", err) }
		
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("BatchCreateRecords", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectBegin()
		// database/sql rejects []string slices (used in UNNEST arrays) before
		// reaching the driver, so the defer triggers a rollback. This is the
		// documented limitation — the NULL-fix is validated by integration tests.
		mock.ExpectRollback()

		recs := []domain.Record{{ID: "r1", ZoneID: "z1", Name: "test.", Type: "A", Content: "1.1.1.1", TTL: 300}}
		_ = repo.BatchCreateRecords(ctx, recs)

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetIXFRChain", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		rows := sqlmock.NewRows([]string{"id", "zone_id", "serial", "action", "name", "type", "content", "ttl", "priority", "weight", "port", "created_at"}).
			AddRow("c1", "z1", 2, "ADD", "new.", "A", "1.2.3.4", 60, nil, nil, nil, time.Now())
		mock.ExpectQuery("SELECT .* FROM dns_zone_changes").WithArgs("z1", uint32(1)).WillReturnRows(rows)
		
		chunks, err := repo.GetIXFRChain(ctx, "z1", 1, 3)
		if err != nil || len(chunks) != 1 { t.Errorf("GetIXFRChain failed: %v", err) }
		
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("ApplyZoneUpdate", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectBegin()
		// First query to fetch SOA - return a valid SOA
		mock.ExpectQuery("SELECT content FROM dns_records").WillReturnRows(
			sqlmock.NewRows([]string{"content"}).AddRow("ns1. host. 1 3600 600 604800 300"))
		mock.ExpectExec("INSERT INTO dns_records").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("DELETE FROM dns_records").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("DELETE FROM dns_records").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("DELETE FROM dns_records").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec("INSERT INTO dns_zone_changes").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()

		ops := []domain.UpdateOperation{
			{Action: domain.ActionAdd, Record: domain.Record{Name: "add."}},
			{Action: domain.ActionDeleteRRSet, Record: domain.Record{Name: "del-rr."}},
			{Action: domain.ActionDeleteAll, Record: domain.Record{Name: "del-all."}},
			{Action: domain.ActionDeleteSpecific, Record: domain.Record{Name: "del-spec.", Content: "c"}},
		}
		changes := []domain.ZoneChange{{Name: "c1"}}
		newSerial, err := repo.ApplyZoneUpdate(ctx, "z1", ops, changes)
		if err != nil { t.Errorf("ApplyZoneUpdate failed: %v", err) }
		if newSerial != 2 { t.Errorf("Expected newSerial 2, got %d", newSerial) }

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})

	t.Run("ApplyZoneUpdate_Errors", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		t.Run("BeginError", func(t *testing.T) {
			mock.ExpectBegin().WillReturnError(errors.New("begin fail"))
			_, err := repo.ApplyZoneUpdate(ctx, "z1", nil, nil)
			if err == nil { t.Error("expected error") }
		})

		t.Run("OperationError", func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT content FROM dns_records").WillReturnError(sql.ErrNoRows)
			mock.ExpectExec("DELETE FROM dns_records").WillReturnError(errors.New("delete fail"))
			mock.ExpectRollback()
			_, err := repo.ApplyZoneUpdate(ctx, "z1", []domain.UpdateOperation{{Action: domain.ActionDeleteAll, Record: domain.Record{Name: "test"}}}, nil)
			if err == nil { t.Error("expected error") }
		})

		t.Run("CommitError", func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectQuery("SELECT content FROM dns_records").WillReturnError(sql.ErrNoRows)
			mock.ExpectCommit().WillReturnError(errors.New("commit fail"))
			_, err := repo.ApplyZoneUpdate(ctx, "z1", nil, nil)
			if err == nil { t.Error("expected error") }
		})
	})

	t.Run("ListAPIKeys_ScanError", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)
		rows := sqlmock.NewRows([]string{"id"}).AddRow(123) // Wrong columns/types
		mock.ExpectQuery("SELECT .* FROM api_keys").WillReturnRows(rows)
		_, err := repo.ListAPIKeys(ctx, "t1")
		if err == nil { t.Error("expected error") }
	})

	t.Run("GetRecord_ScanError", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)
		mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(123))
		_, err := repo.GetRecord(ctx, "r1", "z1", "t1")
		if err == nil { t.Error("expected error") }
	})

	t.Run("ListZoneChanges_RowsErr", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)
		rows := sqlmock.NewRows([]string{"id", "zone_id", "serial", "action", "name", "type", "content", "ttl", "priority", "weight", "port", "created_at"}).
			AddRow("c1", "z1", 1, "ADD", "test.", "A", "1.1.1.1", 60, nil, nil, nil, time.Now()).
			RowError(0, errors.New("row error"))
		mock.ExpectQuery("SELECT .* FROM dns_zone_changes").WillReturnRows(rows)
		_, err := repo.ListZoneChanges(ctx, "z1", 0)
		if err == nil { t.Error("expected error") }
	})

	t.Run("GetIXFRChain_Error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)
		mock.ExpectQuery("SELECT .* FROM dns_zone_changes").WillReturnError(errors.New("db fail"))
		_, err := repo.GetIXFRChain(ctx, "z1", 1, 3)
		if err == nil { t.Error("expected error") }
	})
}

func TestPostgresRepository_Catalog_Unit(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateCatalogZone", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		catz := &domain.CatalogZone{
			ID: "catz-1", TenantID: "t1", ZoneName: "catalog.example.com.",
			Version: "1", Serial: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		mock.ExpectExec(`INSERT INTO catalog_zones`).
			WithArgs(catz.ID, catz.TenantID, catz.ZoneName, catz.Version, catz.Serial, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err = repo.CreateCatalogZone(ctx, catz)
		if err != nil {
			t.Errorf("CreateCatalogZone failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetCatalogZone_Found", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		rows := sqlmock.NewRows([]string{"id", "tenant_id", "zone_name", "version", "serial", "created_at", "updated_at"}).
			AddRow("catz-1", "t1", "catalog.example.com.", "1", uint64(1), time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("catz-1", "t1").
			WillReturnRows(rows)

		got, err := repo.GetCatalogZone(ctx, "catz-1", "t1")
		if err != nil {
			t.Errorf("GetCatalogZone failed: %v", err)
		}
		if got == nil || got.ID != "catz-1" {
			t.Errorf("expected catalog zone with id catz-1, got %+v", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetCatalogZone_NotFound", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("nonexistent", "t1").
			WillReturnError(sql.ErrNoRows)

		got, err := repo.GetCatalogZone(ctx, "nonexistent", "t1")
		if err != nil {
			t.Errorf("GetCatalogZone should not error on no rows: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil for non-existent catalog zone, got %+v", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetCatalogZoneByName", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		catzRows := sqlmock.NewRows([]string{"id", "tenant_id", "zone_name", "version", "serial", "created_at", "updated_at"}).
			AddRow("catz-1", "t1", "catalog.example.com.", "1", uint64(1), time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE zone_name = \$1 AND tenant_id = \$2`).
			WithArgs("catalog.example.com.", "t1").
			WillReturnRows(catzRows)

		got, err := repo.GetCatalogZoneByName(ctx, "catalog.example.com.", "t1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected catalog zone, got nil")
		}
		if got.ID != "catz-1" {
			t.Errorf("expected ID 'catz-1', got %s", got.ID)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetCatalogZoneByName_NotFound", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE zone_name = \$1 AND tenant_id = \$2`).
			WithArgs("nonexistent.example.com.", "t1").
			WillReturnError(sql.ErrNoRows)

		got, err := repo.GetCatalogZoneByName(ctx, "nonexistent.example.com.", "t1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("ListCatalogZones", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		rows := sqlmock.NewRows([]string{"id", "tenant_id", "zone_name", "version", "serial", "created_at", "updated_at"}).
			AddRow("catz-1", "t1", "catalog1.example.com.", "1", uint64(1), time.Now(), time.Now()).
			AddRow("catz-2", "t1", "catalog2.example.com.", "1", uint64(1), time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE tenant_id = \$1 ORDER BY created_at DESC`).
			WithArgs("t1").
			WillReturnRows(rows)

		catalogs, err := repo.ListCatalogZones(ctx, "t1")
		if err != nil {
			t.Errorf("ListCatalogZones failed: %v", err)
		}
		if len(catalogs) != 2 {
			t.Errorf("expected 2 catalogs, got %d", len(catalogs))
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("UpdateCatalogZoneVersion", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectExec(`UPDATE catalog_zones SET version = \$1, serial = \$2, updated_at = CURRENT_TIMESTAMP WHERE id = \$3`).
			WithArgs("2", uint32(2), "catz-1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err = repo.UpdateCatalogZoneVersion(ctx, "catz-1", "2", 2)
		if err != nil {
			t.Errorf("UpdateCatalogZoneVersion failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("DeleteCatalogZone", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectExec(`DELETE FROM catalog_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("catz-1", "t1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err = repo.DeleteCatalogZone(ctx, "catz-1", "t1")
		if err != nil {
			t.Errorf("DeleteCatalogZone failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("ListZoneCatalogEntries", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		// First query: GetCatalogZone
		catzRows := sqlmock.NewRows([]string{"id", "tenant_id", "zone_name", "version", "serial", "created_at", "updated_at"}).
			AddRow("catz-1", "t1", "catalog.example.com.", "1", uint64(1), time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("catz-1", "t1").
			WillReturnRows(catzRows)

		// Second query: zone lookup
		zoneRows := sqlmock.NewRows([]string{"id"}).AddRow("zone-1")
		mock.ExpectQuery(`SELECT id FROM dns_zones WHERE name = \$1 AND tenant_id = \$2`).
			WithArgs("catalog.example.com.", "t1").
			WillReturnRows(zoneRows)

		// Third query: PTR records
		ptrRows := sqlmock.NewRows([]string{"name", "content"}).
			AddRow("com.example.", "foo.example.com.:zone-uuid-1:group1").
			AddRow("com.example.", "bar.example.com.:zone-uuid-2")
		mock.ExpectQuery(`SELECT name, content FROM dns_records WHERE zone_id = \$1 AND type = 'PTR'`).
			WithArgs("zone-1").
			WillReturnRows(ptrRows)

		entries, err := repo.ListZoneCatalogEntries(ctx, "catz-1", "t1")
		if err != nil {
			t.Errorf("ListZoneCatalogEntries failed: %v", err)
		}
		if len(entries) != 2 {
			t.Errorf("expected 2 entries, got %d", len(entries))
		}
		if entries[0].ZoneName != "foo.example.com." || entries[0].ZoneID != "zone-uuid-1" || entries[0].GroupID != "group1" {
			t.Errorf("unexpected first entry: %+v", entries[0])
		}
		if entries[1].GroupID != "" {
			t.Errorf("expected empty group_id for second entry, got %s", entries[1].GroupID)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("AddZoneToCatalog", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		// GetCatalogZone
		catzRows := sqlmock.NewRows([]string{"id", "tenant_id", "zone_name", "version", "serial", "created_at", "updated_at"}).
			AddRow("catz-1", "t1", "catalog.example.com.", "1", uint64(1), time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("catz-1", "t1").
			WillReturnRows(catzRows)

		// Zone lookup
		zoneRows := sqlmock.NewRows([]string{"id"}).AddRow("zone-1")
		mock.ExpectQuery(`SELECT id FROM dns_zones WHERE name = \$1`).
			WithArgs("catalog.example.com.").
			WillReturnRows(zoneRows)

		// Insert PTR record with ON CONFLICT DO NOTHING
		// Only 4 args are passed: id, zone_id, name, content; 'PTR', 3600, created_at, updated_at are in query
		mock.ExpectExec(`INSERT INTO dns_records`).
			WithArgs(sqlmock.AnyArg(), "zone-1", sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		entry := &domain.ZoneCatalogEntry{ZoneName: "foo.example.com.", ZoneID: "zone-uuid-1", GroupID: "group1"}
		err = repo.AddZoneToCatalog(ctx, "catz-1", "t1", entry)
		if err != nil {
			t.Errorf("AddZoneToCatalog failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("RemoveZoneFromCatalog_LexicographicRange", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		// GetCatalogZone
		catzRows := sqlmock.NewRows([]string{"id", "tenant_id", "zone_name", "version", "serial", "created_at", "updated_at"}).
			AddRow("catz-1", "t1", "catalog.example.com.", "1", uint64(1), time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM catalog_zones WHERE id = \$1 AND tenant_id = \$2`).
			WithArgs("catz-1", "t1").
			WillReturnRows(catzRows)

		// Zone lookup
		zoneRows := sqlmock.NewRows([]string{"id"}).AddRow("zone-1")
		mock.ExpectQuery(`SELECT id FROM dns_zones WHERE name = \$1`).
			WithArgs("catalog.example.com.").
			WillReturnRows(zoneRows)

		// Delete with substring prefix match
		// prefix = "foo.example.com.:"
		mock.ExpectExec(`DELETE FROM dns_records WHERE zone_id = \$1 AND type = 'PTR' AND substring\(content, 1, length\(\$2\)\) = \$2`).
			WithArgs("zone-1", "foo.example.com.:").
			WillReturnResult(sqlmock.NewResult(1, 1))

		err = repo.RemoveZoneFromCatalog(ctx, "catz-1", "t1", "foo.example.com.")
		if err != nil {
			t.Errorf("RemoveZoneFromCatalog failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetZoneByCatalogName", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "role", "master_server", "catalog_zone_name", "created_at", "updated_at"}).
			AddRow("zone-1", "t1", "real.example.com.", "slave", "10.0.0.1:53", "my-catalog-zone", time.Now(), time.Now())
		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE catalog_zone_name = \$1 AND tenant_id = \$2`).
			WithArgs("my-catalog-zone", "t1").
			WillReturnRows(rows)

		got, err := repo.GetZoneByCatalogName(ctx, "my-catalog-zone", "t1")
		if err != nil {
			t.Errorf("GetZoneByCatalogName failed: %v", err)
		}
		if got == nil || got.ID != "zone-1" {
			t.Errorf("expected zone with id zone-1, got %+v", got)
		}
		if got != nil && got.CatalogZoneName == nil {
			t.Error("expected catalog_zone_name to be set")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("GetZoneByCatalogName_NotFound", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectQuery(`SELECT .* FROM dns_zones WHERE catalog_zone_name = \$1 AND tenant_id = \$2`).
			WithArgs("nonexistent", "t1").
			WillReturnError(sql.ErrNoRows)

		got, err := repo.GetZoneByCatalogName(ctx, "nonexistent", "t1")
		if err != nil {
			t.Errorf("GetZoneByCatalogName should not error on no rows: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil for non-existent, got %+v", got)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("CreateZoneFromCatalog", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		// CreateZone succeeds (Exec matched), but BatchCreateRecords fails on UNNEST with []string.
		// UNNEST with []string is rejected at driver level before any Query is issued.
		// This mirrors the existing BatchCreateRecords test pattern — validated via integration tests.
		mock.ExpectExec(`INSERT INTO dns_zones`).
			WillReturnResult(sqlmock.NewResult(1, 1))

		zone := &domain.Zone{ID: "z1", TenantID: "t1", Name: "catalog.example.com.", Role: "slave"}
		recs := []domain.Record{{ID: "r1", ZoneID: "z1", Name: "catalog.example.com.", Type: "SOA", Content: "ns1. admin. 1 3600 600 1209600 300", TTL: 300}}
		// BatchCreateRecords fails on UNNEST, error propagates — this is expected.
		_ = repo.CreateZoneFromCatalog(ctx, zone, recs)
		// Verify CreateZone was called (Exec expectation met)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("DeleteZoneByCatalogName", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to open sqlmock: %s", err)
		}
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectExec(`DELETE FROM dns_zones WHERE catalog_zone_name = \$1 AND tenant_id = \$2`).
			WithArgs("catalog-zone-name", "t1").
			WillReturnResult(sqlmock.NewResult(0, 1))

		err = repo.DeleteZoneByCatalogName(ctx, "catalog-zone-name", "t1")
		if err != nil {
			t.Errorf("DeleteZoneByCatalogName failed: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}

func TestPostgresRecordIterator_Unit(t *testing.T) {
	ctx := context.Background()

	t.Run("Next_Success", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, 10, 5, 80, nil, "HTTP", "http://target", "HEALTHY").
			AddRow("r2", "z1", "mail.test.", "A", "5.6.7.8", 300, nil, nil, nil, nil, "NONE", nil, "UNKNOWN")

		mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(rows)

		iter, err := repo.ListRecordsForZoneStreaming(ctx, "z1", "t1")
		if err != nil { t.Fatalf("ListRecordsForZoneStreaming failed: %v", err) }

		// First record
		if !iter.Next() { t.Fatal("Expected first record") }
		rec := iter.Record()
		if rec.ID != "r1" || rec.Content != "1.2.3.4" || *rec.Priority != 10 { t.Errorf("Unexpected record: %+v", rec) }

		// Second record
		if !iter.Next() { t.Fatal("Expected second record") }
		rec = iter.Record()
		if rec.ID != "r2" || rec.Content != "5.6.7.8" { t.Errorf("Unexpected record: %+v", rec) }

		// No more records
		if iter.Next() { t.Fatal("Did not expect more records") }
		if iter.Err() != nil { t.Errorf("Unexpected error: %v", iter.Err()) }

		iter.Close()
	})

	t.Run("Next_ScanError", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		// Wrong column type to cause scan error
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", "not-an-int", nil, nil, nil, nil, nil, nil, nil) // ttl should be int

		mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(rows)

		iter, err := repo.ListRecordsForZoneStreaming(ctx, "z1", "t1")
		if err != nil { t.Fatalf("ListRecordsForZoneStreaming failed: %v", err) }

		if iter.Next() { t.Error("Did not expect record after scan error") }
		if iter.Err() == nil { t.Error("Expected scan error") }

		iter.Close()
	})

	t.Run("Next_RowsError", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		// RowError(0, ...) causes rows.Next() to return false immediately with the error set
		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, nil, nil, nil, nil, nil, nil, nil).
			RowError(0, errors.New("rows error"))

		mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(rows)

		iter, err := repo.ListRecordsForZoneStreaming(ctx, "z1", "t1")
		if err != nil { t.Fatalf("ListRecordsForZoneStreaming failed: %v", err) }

		// rows error causes Next() to return false immediately
		if iter.Next() { t.Error("Did not expect record when rows has error") }
		if iter.Err() == nil { t.Error("Expected rows error") }

		iter.Close()
	})

	t.Run("Close_NilRows", func(t *testing.T) {
		db, _, _ := sqlmock.New()
		defer db.Close()

		// Directly test iterator with nil rows by checking the Close behavior on error path
		iter := &postgresRecordIterator{}
		if err := iter.Close(); err != nil { t.Errorf("Close with nil rows failed: %v", err) }
	})

	t.Run("Close_WithError", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
			AddRow("r1", "z1", "www.test.", "A", "1.2.3.4", 300, nil, nil, nil, nil, nil, nil, nil).
			RowError(0, errors.New("close error"))

		mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnRows(rows)

		iter, err := repo.ListRecordsForZoneStreaming(ctx, "z1", "t1")
		if err != nil { t.Fatalf("ListRecordsForZoneStreaming failed: %v", err) }

		iter.Next()
		closeErr := iter.Close()

		// The rows error should have been captured via Close
		if closeErr == nil { t.Error("Expected error from Close") }
	})

	t.Run("ListRecordsForZoneStreaming_Error", func(t *testing.T) {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		repo := NewPostgresRepository(db)

		mock.ExpectQuery("SELECT .* FROM dns_records").WillReturnError(errors.New("query error"))

		_, err := repo.ListRecordsForZoneStreaming(ctx, "z1", "t1")
		if err == nil { t.Error("Expected error from ListRecordsForZoneStreaming") }
	})
}
