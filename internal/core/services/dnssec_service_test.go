package services

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type mockDNSSECRepo struct {
	keys []domain.DNSSECKey
	err  error
}

func (m *mockDNSSECRepo) GetRecords(_ context.Context, _ string, _ domain.RecordType, _ string) ([]domain.Record, error) { return nil, nil }
func (m *mockDNSSECRepo) GetIPsForName(_ context.Context, _ string, _ string) ([]string, error) { return nil, nil }
func (m *mockDNSSECRepo) GetZone(_ context.Context, _ string) (*domain.Zone, error) { return nil, nil }
func (m *mockDNSSECRepo) GetRecord(_ context.Context, _ string, _ string) (*domain.Record, error) { return nil, nil }
func (m *mockDNSSECRepo) ListRecordsForZone(_ context.Context, _ string) ([]domain.Record, error) { return nil, nil }
func (m *mockDNSSECRepo) CreateZone(_ context.Context, _ *domain.Zone) error { return nil }
func (m *mockDNSSECRepo) CreateZoneWithRecords(_ context.Context, _ *domain.Zone, _ []domain.Record) error { return nil }
func (m *mockDNSSECRepo) CreateRecord(_ context.Context, _ *domain.Record) error { return nil }
func (m *mockDNSSECRepo) ListZones(_ context.Context, _ string) ([]domain.Zone, error) { return nil, nil }
func (m *mockDNSSECRepo) DeleteZone(_ context.Context, _, _ string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecord(_ context.Context, _, _ string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordsByNameAndType(_ context.Context, _, _ string, _ domain.RecordType) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordsByName(_ context.Context, _, _ string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordSpecific(_ context.Context, _, _ string, _ domain.RecordType, _ string) error { return nil }
func (m *mockDNSSECRepo) RecordZoneChange(_ context.Context, _ *domain.ZoneChange) error { return nil }
func (m *mockDNSSECRepo) ListZoneChanges(_ context.Context, _ string, _ uint32) ([]domain.ZoneChange, error) { return nil, nil }
func (m *mockDNSSECRepo) SaveAuditLog(_ context.Context, _ *domain.AuditLog) error { return nil }
func (m *mockDNSSECRepo) GetAuditLogs(_ context.Context, _ string) ([]domain.AuditLog, error) { return nil, nil }
func (m *mockDNSSECRepo) Ping(_ context.Context) error { return nil }

func (m *mockDNSSECRepo) CreateKey(_ context.Context, key *domain.DNSSECKey) error {
	if m.err != nil { return m.err }
	m.keys = append(m.keys, *key)
	return nil
}

func (m *mockDNSSECRepo) ListKeysForZone(_ context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	if m.err != nil { return nil, m.err }
	var result []domain.DNSSECKey
	for _, k := range m.keys {
		if k.ZoneID == zoneID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (m *mockDNSSECRepo) UpdateKey(_ context.Context, key *domain.DNSSECKey) error {
	if m.err != nil { return m.err }
	for i, k := range m.keys {
		if k.ID == key.ID {
			m.keys[i] = *key
			return nil
		}
	}
	return nil
}

// TestGenerateKey verifies that the service can generate valid ECDSA P-256 keys.
func TestGenerateKey(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	key, err := svc.GenerateKey(ctx, "zone-1", "KSK")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if key.KeyType != "KSK" || key.Algorithm != 13 {
		t.Errorf("Invalid key metadata: %+v", key)
	}
	if len(key.PrivateKey) == 0 || len(key.PublicKey) == 0 {
		t.Errorf("Keys were not generated")
	}

	// Error case
	repo.err = errors.New("db error")
	_, err = svc.GenerateKey(ctx, "zone-1", "KSK")
	if err == nil {
		t.Errorf("Expected error in GenerateKey when repo fails")
	}
}

// TestAutomateLifecycle verifies that the background worker can detect
// missing keys and automatically generate them for a zone.
func TestAutomateLifecycle(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// 1. Run on a zone with no keys
	if err := svc.AutomateLifecycle(ctx, "zone-1"); err != nil {
		t.Fatalf("AutomateLifecycle failed: %v", err)
	}

	// 2. Verify both KSK and ZSK were created
	keys, _ := repo.ListKeysForZone(ctx, "zone-1")
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}

	hasKSK := false
	hasZSK := false
	for _, k := range keys {
		if k.KeyType == "KSK" { hasKSK = true }
		if k.KeyType == "ZSK" { hasZSK = true }
	}
	if !hasKSK || !hasZSK {
		t.Errorf("AutomateLifecycle failed to create both required key types")
	}

	// 3. Error case
	repo.err = errors.New("list fail")
	if err := svc.AutomateLifecycle(ctx, "z2"); err == nil {
		t.Errorf("Expected error in AutomateLifecycle when list fail")
	}
}

func TestAutomateLifecycle_ExistingKeys(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Setup: Existing active keys with recent timestamps
	now := time.Now()
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID: "k1", ZoneID: "z1", KeyType: "KSK", Active: true, CreatedAt: now,
	})
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID: "k2", ZoneID: "z1", KeyType: "ZSK", Active: true, CreatedAt: now,
	})

	// Run automation
	if err := svc.AutomateLifecycle(ctx, "z1"); err != nil {
		t.Fatalf("AutomateLifecycle failed: %v", err)
	}

	// Should not have added any more keys
	if len(repo.keys) != 2 {
		t.Errorf("Expected still 2 keys, got %d", len(repo.keys))
	}
}

func TestGetActiveKeys(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Setup: One inactive, one active key
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID: "k1", ZoneID: "z1", KeyType: "ZSK", Active: false,
	})
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID: "k2", ZoneID: "z1", KeyType: "ZSK", Active: true,
	})

	keys, err := svc.GetActiveKeys(ctx, "z1", "ZSK")
	if err != nil {
		t.Fatalf("GetActiveKeys failed: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != "k2" {
		t.Errorf("Expected only k2 active, got %d keys", len(keys))
	}

	_, err = svc.GetActiveKeys(ctx, "z1", "KSK")
	if err == nil {
		t.Errorf("Expected error for missing KSK")
	}
}

func TestSignRRSet(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// 1. Setup ZSK
	_, err := svc.GenerateKey(ctx, "z1", "ZSK")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// 2. Sign a dummy RRSet
	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	sigs, err := svc.SignRRSet(ctx, "example.com.", "z1", records)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	if len(sigs) != 1 {
		t.Fatalf("Expected 1 RRSIG record, got %d", len(sigs))
	}
	sig := sigs[0]
	if sig.Type != packet.RRSIG {
		t.Errorf("Expected RRSIG type, got %v", sig.Type)
	}
	if sig.TypeCovered != uint16(packet.A) {
		t.Errorf("Expected TypeCovered A, got %d", sig.TypeCovered)
	}
	if len(sig.Signature) == 0 {
		t.Errorf("Signature is empty")
	}

	// 3. Test empty RRSet
	sigsEmpty, err := svc.SignRRSet(ctx, "example.com.", "z1", nil)
	if err != nil || len(sigsEmpty) != 0 {
		t.Errorf("Expected (nil, nil) for empty RRSet, got (%v, %v)", sigsEmpty, err)
	}

	// 4. Test Sign fail (no active key)
	_, err = svc.SignRRSet(ctx, "e.com.", "unknown", records)
	if err == nil {
		t.Errorf("Expected error when no active key found")
	}
}

func TestAutomateLifecycle_Rollover(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// 1. Create an old ZSK
	oldTime := time.Now().Add(-40 * 24 * time.Hour) // 40 days old
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID: "k1", ZoneID: "z1", KeyType: "ZSK", Active: true, CreatedAt: oldTime,
	})
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID: "k2", ZoneID: "z1", KeyType: "KSK", Active: true, CreatedAt: time.Now(),
	})

	// 2. Run automation - should trigger rollover
	if err := svc.AutomateLifecycle(ctx, "z1"); err != nil {
		t.Fatalf("AutomateLifecycle failed: %v", err)
	}

	// 3. Verify a new ZSK was created
	keys, _ := repo.ListKeysForZone(ctx, "z1")
	hasNewZSK := false
	for _, k := range keys {
		if k.KeyType == "ZSK" && time.Since(k.CreatedAt) < time.Minute {
			hasNewZSK = true
		}
	}
	if !hasNewZSK {
		t.Errorf("AutomateLifecycle failed to create new ZSK during rollover")
	}

	// 4. Verify old ZSK is STILL active (Double Signature period)
	var k1 domain.DNSSECKey
	for _, k := range keys { if k.ID == "k1" { k1 = k } }
	if !k1.Active {
		t.Errorf("Old ZSK deactivated too early, should be active during overlap")
	}

	// 5. Simulate time passing past overlap
	k1.CreatedAt = time.Now().Add(-50 * 24 * time.Hour)
	for i, k := range repo.keys { if k.ID == "k1" { repo.keys[i] = k1 } }

	if err := svc.AutomateLifecycle(ctx, "z1"); err != nil {
		t.Fatalf("Second automation failed: %v", err)
	}

	// 6. Verify old ZSK is now deactivated
	keys, _ = repo.ListKeysForZone(ctx, "z1")
	for _, k := range keys {
		if k.ID == "k1" && k.Active {
			t.Errorf("Old ZSK should be deactivated after overlap period")
		}
	}
}
