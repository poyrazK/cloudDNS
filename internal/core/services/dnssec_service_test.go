package services

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type mockDNSSECRepo struct {
	keys []domain.DNSSECKey
}

func (m *mockDNSSECRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) { return nil, nil }
func (m *mockDNSSECRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) { return nil, nil }
func (m *mockDNSSECRepo) GetZone(ctx context.Context, name string) (*domain.Zone, error) { return nil, nil }
func (m *mockDNSSECRepo) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) { return nil, nil }
func (m *mockDNSSECRepo) CreateZone(ctx context.Context, zone *domain.Zone) error { return nil }
func (m *mockDNSSECRepo) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error { return nil }
func (m *mockDNSSECRepo) CreateRecord(ctx context.Context, record *domain.Record) error { return nil }
func (m *mockDNSSECRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) { return nil, nil }
func (m *mockDNSSECRepo) DeleteZone(ctx context.Context, zoneID string, tenantID string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordsByName(ctx context.Context, zoneID string, name string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordSpecific(ctx context.Context, zoneID string, name string, qType domain.RecordType, content string) error { return nil }
func (m *mockDNSSECRepo) RecordZoneChange(ctx context.Context, change *domain.ZoneChange) error { return nil }
func (m *mockDNSSECRepo) ListZoneChanges(ctx context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error) { return nil, nil }
func (m *mockDNSSECRepo) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error { return nil }
func (m *mockDNSSECRepo) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) { return nil, nil }
func (m *mockDNSSECRepo) Ping(ctx context.Context) error { return nil }

func (m *mockDNSSECRepo) CreateKey(ctx context.Context, key *domain.DNSSECKey) error {
	m.keys = append(m.keys, *key)
	return nil
}

func (m *mockDNSSECRepo) ListKeysForZone(ctx context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	var result []domain.DNSSECKey
	for _, k := range m.keys {
		if k.ZoneID == zoneID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (m *mockDNSSECRepo) UpdateKey(ctx context.Context, key *domain.DNSSECKey) error {
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
}
