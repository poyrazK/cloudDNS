package repository

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestPostgresRepository_BatchCreateRecords(t *testing.T) {
	// Skip if no real DB available, but the logic should be covered in E2E.
	// Here we test the empty batch case which is safe.
	db := &PostgresRepository{db: nil}
	err := db.BatchCreateRecords(context.Background(), nil)
	if err != nil {
		t.Errorf("Expected nil error for empty batch, got %v", err)
	}
}

func TestConvertPacketRecordToDomain_Extra(t *testing.T) {
	// Test the edge cases in ConvertPacketRecordToDomain for coverage
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

	// Test unsupported type
	_, err = ConvertPacketRecordToDomain(packet.DNSRecord{Type: 999}, zoneID)
	if err == nil {
		t.Errorf("Expected error for unsupported type 999")
	}
}
