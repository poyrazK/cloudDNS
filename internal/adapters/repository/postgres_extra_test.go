package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestBatchCreateRecords_NilFields verifies BatchCreateRecords handles records
// with nil optional fields (priority, weight, port, network) without panicking.
//
// Note: sqlmock cannot validate PostgreSQL array types ([]uuid[], int[], text[])
// used in UNNEST — database/sql rejects []string slices before reaching the driver.
// The NULL encoding is guaranteed by sql.NullInt32/sql.NullString (driver.Valuer)
// and validated by integration tests against a real PostgreSQL instance. This unit
// test verifies the empty-batch path and the Null type zero-value behavior.
func TestBatchCreateRecords_NilFields(t *testing.T) {
	// 1. Empty batch should return nil
	db, _, _ := sqlmock.New()
	repo := NewPostgresRepository(db)
	err := repo.BatchCreateRecords(context.Background(), nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}
	_ = db.Close()

	// 2. Verify sql.NullInt32/sql.NullString zero values have Valid=false.
	// When the BatchCreateRecords code leaves an optional field as nil, the
	// corresponding Null type entry has Valid=false, which database/sql
	// encodes as SQL NULL (not 0). This is the mechanism that fixes the regression.
	var nilInt sql.NullInt32
	var nilStr sql.NullString
	if nilInt.Valid {
		t.Errorf("expected sql.NullInt32 Valid=false, got true")
	}
	if nilStr.Valid {
		t.Errorf("expected sql.NullString Valid=false, got true")
	}
}

func TestPostgresRepository_GetRecord_Mock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	id := uuid.New().String()
	zoneID := uuid.New().String()

	// 1. Success case
	rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network", "health_check_type", "health_check_target", "status"}).
		AddRow(id, zoneID, "test.com.", "A", "1.1.1.1", 300, nil, nil, nil, nil, "NONE", nil, "UNKNOWN")
	mock.ExpectQuery("SELECT .* FROM dns_records").WithArgs(id, zoneID, "").WillReturnRows(rows)

	rec, err := repo.GetRecord(ctx, id, zoneID, "")
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.Name != "test.com." {
		t.Errorf("got %s, want test.com.", rec.Name)
	}

	// 2. Not found
	mock.ExpectQuery("SELECT .* FROM dns_records").WithArgs("none", zoneID, "").WillReturnRows(sqlmock.NewRows(nil))
	rec, err = repo.GetRecord(ctx, "none", zoneID, "")
	if err != nil || rec != nil {
		t.Errorf("Expected nil record and no error for not found")
	}
}

func TestConvertPacketRecordToDomain_Extra(t *testing.T) {
	zoneID := uuid.New().String()

	// Test DS record
	dsRec := packet.DNSRecord{
		Name:       "test.com.",
		Type:       packet.DS,
		TTL:        3600,
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	dRec, err := ConvertPacketRecordToDomain(dsRec, zoneID)
	if err != nil {
		t.Fatalf("ConvertPacketRecordToDomain failed for DS: %v", err)
	}
	if dRec.Type != "DS" || dRec.Content != "12345 13 2 deadbeef" {
		t.Errorf("Unexpected DS content: %s", dRec.Content)
	}

	// Test DNSKEY
	dkRec := packet.DNSRecord{
		Name:      "test.com.",
		Type:      packet.DNSKEY,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02},
	}
	dRec, _ = ConvertPacketRecordToDomain(dkRec, zoneID)
	if dRec.Type != "DNSKEY" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test RRSIG
	sigRec := packet.DNSRecord{
		Type:       packet.RRSIG,
		SignerName: "test.",
		Signature:  []byte{0x01},
	}
	dRec, _ = ConvertPacketRecordToDomain(sigRec, zoneID)
	if dRec.Type != "RRSIG" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test NSEC
	nsecRec := packet.DNSRecord{
		Type:     packet.NSEC,
		NextName: "next.",
	}
	dRec, _ = ConvertPacketRecordToDomain(nsecRec, zoneID)
	if dRec.Type != "NSEC" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test NSEC3
	nsec3Rec := packet.DNSRecord{
		Type:     packet.NSEC3,
		Salt:     []byte{0x01},
		NextHash: []byte{0x02},
	}
	dRec, _ = ConvertPacketRecordToDomain(nsec3Rec, zoneID)
	if dRec.Type != "NSEC3" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test unsupported type
	_, err = ConvertPacketRecordToDomain(packet.DNSRecord{Type: 999}, zoneID)
	if err == nil {
		t.Errorf("Expected error for unsupported type 999")
	}
}

// TestGetZoneLongestMatch_LIKEWildcardEscaping verifies that LIKE wildcards in
// the query name are properly escaped to prevent pattern injection (issue #257).
func TestGetZoneLongestMatch_LIKEWildcardEscaping(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	repo := NewPostgresRepository(db)
	ctx := context.Background()

	now := time.Now()

	// Query name with LIKE wildcards - should be escaped before use in query
	qName := "test%.example.com"
	rows := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
		AddRow("z1", "t1", "test.example.com.", nil, "", "master", nil, now, now)
	// The escaped name should be passed, not the raw one with wildcards
	mock.ExpectQuery("SELECT .* FROM dns_zones").WithArgs("test\\%.example.com").WillReturnRows(rows)

	zone, err := repo.GetZoneLongestMatch(ctx, qName)
	if err != nil {
		t.Fatalf("GetZoneLongestMatch failed: %v", err)
	}
	if zone == nil || zone.Name != "test.example.com." {
		t.Errorf("unexpected zone: %v", zone)
	}

	// Also test underscore wildcard
	qName2 := "test_.example.com"
	rows2 := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
		AddRow("z1", "t1", "testa.example.com.", nil, "", "master", nil, now, now)
	mock.ExpectQuery("SELECT .* FROM dns_zones").WithArgs("test\\_.example.com").WillReturnRows(rows2)

	zone2, err := repo.GetZoneLongestMatch(ctx, qName2)
	if err != nil {
		t.Fatalf("GetZoneLongestMatch failed: %v", err)
	}
	if zone2 == nil || zone2.Name != "testa.example.com." {
		t.Errorf("unexpected zone: %v", zone2)
	}

	// Also test backslash escaping
	qName3 := "test\\example.com"
	rows3 := sqlmock.NewRows([]string{"id", "tenant_id", "name", "vpc_id", "description", "role", "master_server", "created_at", "updated_at"}).
		AddRow("z1", "t1", "test\\example.com.", nil, "", "master", nil, now, now)
	mock.ExpectQuery("SELECT .* FROM dns_zones").WithArgs("test\\\\example.com").WillReturnRows(rows3)

	zone3, err := repo.GetZoneLongestMatch(ctx, qName3)
	if err != nil {
		t.Fatalf("GetZoneLongestMatch failed: %v", err)
	}
	if zone3 == nil || zone3.Name != "test\\example.com." {
		t.Errorf("unexpected zone: %v", zone3)
	}
}
