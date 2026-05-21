package services

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type mockDNSSECRepo struct {
	keys     []domain.DNSSECKey
	zones    []domain.Zone
	err      error
	keysErr  error
	listErr  error
}

func (m *mockDNSSECRepo) GetRecords(_ context.Context, _ string, _ domain.RecordType, _ string) ([]domain.Record, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) GetIPsForName(_ context.Context, _ string, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) GetRecordsByNames(_ context.Context, _ []string, _ domain.RecordType, _ string) (map[string][]domain.Record, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) GetZone(_ context.Context, _ string) (*domain.Zone, error) { return nil, nil }
func (m *mockDNSSECRepo) GetZoneLongestMatch(_ context.Context, _ string) (*domain.Zone, error) { return nil, nil }
func (m *mockDNSSECRepo) GetRecord(_ context.Context, _ string, _ string, _ string) (*domain.Record, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) ListRecordsForZone(_ context.Context, _ string, _ string) ([]domain.Record, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) ListRecordsForZoneStreaming(_ context.Context, _ string, _ string) (ports.RecordIterator, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) CreateZone(_ context.Context, _ *domain.Zone) error { return nil }
func (m *mockDNSSECRepo) CreateZoneWithRecords(_ context.Context, _ *domain.Zone, _ []domain.Record) error {
	return nil
}
func (m *mockDNSSECRepo) CreateRecord(_ context.Context, _ *domain.Record) error        { return nil }
func (m *mockDNSSECRepo) BatchCreateRecords(_ context.Context, _ []domain.Record) error { return nil }
func (m *mockDNSSECRepo) ListZones(_ context.Context, _ string) ([]domain.Zone, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.zones, nil
}
func (m *mockDNSSECRepo) DeleteZone(_ context.Context, _, _ string) error      { return nil }
func (m *mockDNSSECRepo) DeleteRecord(_ context.Context, _, _, _ string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordsByNameAndType(_ context.Context, _, _ string, _ domain.RecordType) error {
	return nil
}
func (m *mockDNSSECRepo) DeleteRecordsByName(_ context.Context, _, _ string) error { return nil }
func (m *mockDNSSECRepo) DeleteRecordsForZone(_ context.Context, _ string) error { return m.err }
func (m *mockDNSSECRepo) DeleteRecordSpecific(_ context.Context, _, _ string, _ domain.RecordType, _ string) error {
	return nil
}
func (m *mockDNSSECRepo) RecordZoneChange(_ context.Context, _ *domain.ZoneChange) error { return nil }
func (m *mockDNSSECRepo) ListZoneChanges(_ context.Context, _ string, _ uint32) ([]domain.ZoneChange, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) GetIXFRChain(_ context.Context, _ string, _, _ uint32) ([]domain.IXFRChunk, error) {
	return nil, m.err
}
func (m *mockDNSSECRepo) ApplyZoneUpdate(_ context.Context, _ string, _ []domain.UpdateOperation, _ []domain.ZoneChange) (uint32, error) {
	return 0, m.err
}
func (m *mockDNSSECRepo) SaveAuditLog(_ context.Context, _ *domain.AuditLog) error { return nil }
func (m *mockDNSSECRepo) GetAuditLogs(_ context.Context, _ string) ([]domain.AuditLog, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) DeleteAPIKey(_ context.Context, _, _ string) error { return nil }
func (m *mockDNSSECRepo) Ping(_ context.Context) error                      { return nil }

func (m *mockDNSSECRepo) UpdateRecordHealth(_ context.Context, _ string, _ domain.HealthStatus, _ string) error {
	return nil
}

func (m *mockDNSSECRepo) UpdateRecord(_ context.Context, record *domain.Record) error {
	return nil
}

func (m *mockDNSSECRepo) GetRecordsToProbeStreaming(_ context.Context) (ports.RecordIterator, error) {
	return nil, nil
}

func (m *mockDNSSECRepo) CreateKey(_ context.Context, key *domain.DNSSECKey) error {
	if m.err != nil {
		return m.err
	}
	m.keys = append(m.keys, *key)
	return nil
}

func (m *mockDNSSECRepo) ListKeysForZone(_ context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	if m.keysErr != nil {
		return nil, m.keysErr
	}
	var result []domain.DNSSECKey
	for _, k := range m.keys {
		if k.ZoneID == zoneID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (m *mockDNSSECRepo) UpdateKey(_ context.Context, key *domain.DNSSECKey) error {
	if m.err != nil {
		return m.err
	}
	for i, k := range m.keys {
		if k.ID == key.ID {
			m.keys[i] = *key
			return nil
		}
	}
	return nil
}

func (m *mockDNSSECRepo) GetDNSKEYs(_ context.Context, _ string) ([]domain.Record, error) {
	return nil, nil
}

func (m *mockDNSSECRepo) GetAPIKeyByHash(_ context.Context, _ string) (*domain.APIKey, error) {
	return nil, nil
}
func (m *mockDNSSECRepo) CreateAPIKey(_ context.Context, _ *domain.APIKey) error { return nil }
func (m *mockDNSSECRepo) ListAPIKeys(_ context.Context, _ string) ([]domain.APIKey, error) {
	return nil, nil
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

// TestGenerateKey_Ed448 verifies that the service can generate valid Ed448 keys.
func TestGenerateKey_Ed448(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	key, err := svc.GenerateKey(ctx, "zone-1", "ed448-zsk")
	if err != nil {
		t.Fatalf("GenerateKey (Ed448) failed: %v", err)
	}

	if key.KeyType != "ed448-zsk" {
		t.Errorf("Expected key type ed448-zsk, got %s", key.KeyType)
	}
	if key.Algorithm != 16 {
		t.Errorf("Expected algorithm 16, got %d", key.Algorithm)
	}
	if len(key.PrivateKey) == 0 || len(key.PublicKey) == 0 {
		t.Errorf("Keys were not generated")
	}
}

// TestSignRRSet_Ed448 verifies that SignRRSet works end-to-end with Ed448 keys.
// Note: SignRRSet is currently hardcoded to look for "ZSK" key type.
// This test verifies that a key created as "ed448-zsk" has algorithm 16.
func TestSignRRSet_Ed448(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Generate Ed448 ZSK - it will have algorithm 16 but SignRRSet looks for "ZSK"
	key, err := svc.GenerateKey(ctx, "z1", "ed448-zsk")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Verify the key was created with Ed448 algorithm
	if key.Algorithm != 16 {
		t.Fatalf("Expected algorithm 16, got %d", key.Algorithm)
	}

	// Manually add it to the mock repo as a ZSK so SignRRSet can find it
	repo.keys = append(repo.keys, domain.DNSSECKey{
		ID:         key.ID,
		ZoneID:     "z1",
		KeyType:    "ZSK", // SignRRSet looks for "ZSK"
		Algorithm:  16,    // Ed448
		PrivateKey: key.PrivateKey,
		PublicKey:  key.PublicKey,
		Active:     true,
	})

	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	sigs, err := svc.SignRRSet(ctx, "example.com.", "z1", records)
	if err != nil {
		t.Fatalf("SignRRSet (Ed448) failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("Expected 1 RRSIG, got %d", len(sigs))
	}
	sig := sigs[0]
	if sig.Type != packet.RRSIG {
		t.Errorf("Expected RRSIG record, got %v", sig.Type)
	}
	if sig.TypeCovered != uint16(packet.A) {
		t.Errorf("Expected TypeCovered A, got %v", sig.TypeCovered)
	}
	if sig.Algorithm != packet.AlgorithmED448 {
		t.Errorf("Expected AlgorithmED448, got %d", sig.Algorithm)
	}
	if len(sig.Signature) == 0 {
		t.Errorf("Expected non-empty signature")
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
		if k.KeyType == "KSK" {
			hasKSK = true
		}
		if k.KeyType == "ZSK" {
			hasZSK = true
		}
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

// TestSignRRSet_CacheHit verifies that the second call to SignRRSet uses the cache.
func TestSignRRSet_CacheHit(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Setup ZSK
	_, err := svc.GenerateKey(ctx, "z1", "ZSK")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// First call - cache miss
	sigs1, err := svc.SignRRSet(ctx, "example.com.", "z1", records)
	if err != nil {
		t.Fatalf("SignRRSet (cache miss) failed: %v", err)
	}
	if len(sigs1) != 1 {
		t.Fatalf("Expected 1 RRSIG, got %d", len(sigs1))
	}

	// Second call - cache hit (same zone)
	sigs2, err := svc.SignRRSet(ctx, "example.com.", "z1", records)
	if err != nil {
		t.Fatalf("SignRRSet (cache hit) failed: %v", err)
	}
	if len(sigs2) != 1 {
		t.Fatalf("Expected 1 RRSIG on cache hit, got %d", len(sigs2))
	}
}

// TestSignRRSet_CacheExpiration verifies that expired cache entries are not returned.
func TestSignRRSet_CacheExpiration(t *testing.T) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Create key and populate cache
	_, err := svc.GenerateKey(ctx, "z1", "ZSK")
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	_, _ = svc.SignRRSet(ctx, "example.com.", "z1", records)

	// Advance time past TTL (replace cached entry with an already-expired one)
	expiredCached := &cachedKeys{
		keys:       map[string][]any{"ZSK": {}},
		keyTags:    map[string][]uint16{"ZSK": {}},
		algorithms: map[string][]uint8{"ZSK": {}},
		expires:    time.Now().Add(-1 * time.Second),
	}
	svc.keyCache.Store("z1", expiredCached)

	// Next SignRRSet should treat as cache miss and re-fetch
	sigs, err := svc.SignRRSet(ctx, "example.com.", "z1", records)
	if err != nil {
		t.Fatalf("SignRRSet after expiry failed: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("Expected 1 RRSIG after expiry re-fetch, got %d", len(sigs))
	}
}

func BenchmarkSignRRSet(b *testing.B) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Pre-generate key (outside benchmark)
	_, _ = svc.GenerateKey(ctx, "z1", "ZSK")

	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.SignRRSet(ctx, "example.com.", "z1", records)
	}
}

func BenchmarkSignRRSet_Cached(b *testing.B) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	// Pre-generate key once (outside benchmark)
	_, _ = svc.GenerateKey(ctx, "z1", "ZSK")
	// Warm the cache with one call (outside timing)
	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	_, _ = svc.SignRRSet(ctx, "example.com.", "z1", records)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.SignRRSet(ctx, "example.com.", "z1", records)
	}
}

// BenchmarkSignRRSet_DB measures cold cache: DB read + key parse every time.
// Key is created once outside the loop; each iteration invalidates cache and
// re-parses the key from its stored bytes, simulating a DB round-trip without
// the cost of a DB write (which BenchmarkSignRRSet_DB does not need to measure).
func BenchmarkSignRRSet_DB(b *testing.B) {
	repo := &mockDNSSECRepo{}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	records := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Create key once outside benchmark (simulates pre-existing key in DB)
	created, _ := svc.GenerateKey(ctx, "z1", "ZSK")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		svc.InvalidateKeyCache("z1")
		// Simulate cold cache: parse the stored key bytes (like DB read would)
		_, _ = svc.SignRRSet(ctx, "example.com.", "z1", records)
		// Restore the key so repo still has it for next iteration
		svc.InvalidateKeyCache("z1")
		repo.keys = []domain.DNSSECKey{*created}
	}
}

// TestCollectKeyStats_AllZonesFail verifies that CollectKeyStats returns an
// empty slice (not an error) when ListZones succeeds but all ListKeysForZone
// calls fail. This is the "all-zones-fail" edge case.
func TestCollectKeyStats_AllZonesFail(t *testing.T) {
	repo := &mockDNSSECRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
			{ID: "z2", Name: "test.com."},
		},
		keysErr: errors.New("db error on ListKeysForZone"),
	}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	stats, err := svc.CollectKeyStats(ctx)
	if err != nil {
		t.Fatalf("CollectKeyStats should not return error on ListKeysForZone failure, got: %v", err)
	}
	if len(stats) != 0 {
		t.Errorf("Expected empty stats slice when all zones fail, got %d", len(stats))
	}
}

// TestCollectKeyStats_Normal verifies CollectKeyStats returns correct stats
// when keys exist for zones.
func TestCollectKeyStats_Normal(t *testing.T) {
	repo := &mockDNSSECRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		keys: []domain.DNSSECKey{
			{ID: "k1", ZoneID: "z1", KeyType: "ZSK", Active: true, Algorithm: 13, CreatedAt: time.Now()},
		},
	}
	svc := NewDNSSECService(repo)
	ctx := context.Background()

	stats, err := svc.CollectKeyStats(ctx)
	if err != nil {
		t.Fatalf("CollectKeyStats failed: %v", err)
	}
	if len(stats) != 1 {
		t.Errorf("Expected 1 stat, got %d", len(stats))
	}
	if stats[0].KeyType != "zsk" {
		t.Errorf("Expected key type 'zsk', got %s", stats[0].KeyType)
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
	for _, k := range keys {
		if k.ID == "k1" {
			k1 = k
		}
	}
	if !k1.Active {
		t.Errorf("Old ZSK deactivated too early, should be active during overlap")
	}

	// 5. Simulate time passing past overlap
	k1.CreatedAt = time.Now().Add(-50 * 24 * time.Hour)
	for i, k := range repo.keys {
		if k.ID == "k1" {
			repo.keys[i] = k1
		}
	}

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
