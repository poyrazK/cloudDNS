package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestPostgresRepository_BatchCreateRecords(t *testing.T) {
	db := &PostgresRepository{db: nil}
	err := db.BatchCreateRecords(context.Background(), nil)
	if err != nil {
		t.Errorf("Expected nil error for empty batch, got %v", err)
	}
}

func TestPostgresRepository_GetRecord_Mock(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewPostgresRepository(db)
	ctx := context.Background()
	id := uuid.New().String()
	zoneID := uuid.New().String()

	// 1. Success case
	rows := sqlmock.NewRows([]string{"id", "zone_id", "name", "type", "content", "ttl", "priority", "weight", "port", "network"}).
		AddRow(id, zoneID, "test.com.", "A", "1.1.1.1", 300, nil, nil, nil, nil)
	mock.ExpectQuery("SELECT .* FROM dns_records").WithArgs(id, zoneID).WillReturnRows(rows)

	rec, err := repo.GetRecord(ctx, id, zoneID)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.Name != "test.com." {
		t.Errorf("got %s, want test.com.", rec.Name)
	}

	// 2. Not found
	mock.ExpectQuery("SELECT .* FROM dns_records").WithArgs("none", zoneID).WillReturnRows(sqlmock.NewRows(nil))
	rec, err = repo.GetRecord(ctx, "none", zoneID)
	if err != nil || rec != nil {
		t.Errorf("Expected nil record and no error for not found")
	}
}

func TestConvertPacketRecordToDomain_Extra(t *testing.T) {
	zoneID := uuid.New().String()
	
	// Test DS record
	dsRec := packet.DNSRecord{
		Name: "test.com.",
		Type: packet.DS,
		TTL: 3600,
		KeyTag: 12345,
		Algorithm: 13,
		DigestType: 2,
		Digest: []byte{0xDE, 0xAD, 0xBE, 0xEF},
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
		Name: "test.com.",
		Type: packet.DNSKEY,
		Flags: 256,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02},
	}
	dRec, _ = ConvertPacketRecordToDomain(dkRec, zoneID)
	if dRec.Type != "DNSKEY" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test RRSIG
	sigRec := packet.DNSRecord{
		Type: packet.RRSIG,
		SignerName: "test.",
		Signature: []byte{0x01},
	}
	dRec, _ = ConvertPacketRecordToDomain(sigRec, zoneID)
	if dRec.Type != "RRSIG" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test NSEC
	nsecRec := packet.DNSRecord{
		Type: packet.NSEC,
		NextName: "next.",
	}
	dRec, _ = ConvertPacketRecordToDomain(nsecRec, zoneID)
	if dRec.Type != "NSEC" {
		t.Errorf("got %s", dRec.Type)
	}

	// Test NSEC3
	nsec3Rec := packet.DNSRecord{
		Type: packet.NSEC3,
		Salt: []byte{0x01},
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
