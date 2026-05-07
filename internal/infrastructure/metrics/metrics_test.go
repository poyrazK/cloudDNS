package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestMetricsDeclarations(t *testing.T) {
	tests := []struct {
		name   string
		metric interface{}
	}{
		// Original
		{"QueriesTotal", QueriesTotal},
		{"QueryDuration", QueryDuration},
		{"CacheOperations", CacheOperations},
		{"ActiveWorkers", ActiveWorkers},
		{"DBConnectionsActive", DBConnectionsActive},
		{"BGPAnnounced", BGPAnnounced},
		// New
		{"CacheHitRatio", CacheHitRatio},
		{"DNSSECKeysTotal", DNSSECKeysTotal},
		{"DNSSECKeysAgeSeconds", DNSSECKeysAgeSeconds},
		{"DNSSECZonesSigned", DNSSECZonesSigned},
		{"NotifiesTotal", NotifiesTotal},
		{"RateLimitedTotal", RateLimitedTotal},
		{"AXFRBytesTotal", AXFRBytesTotal},
		{"RecursiveResolutionsTotal", RecursiveResolutionsTotal},
		{"ZonesTotal", ZonesTotal},
		{"RecordsTotal", RecordsTotal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.metric == nil {
				t.Errorf("%s is nil", tt.name)
			}
		})
	}
}

func TestDNSBuckets(t *testing.T) {
	if len(DNSBuckets) == 0 {
		t.Fatal("DNSBuckets is empty")
	}

	// Verify minimum is sub-millisecond (50µs)
	if DNSBuckets[0] != 0.00005 {
		t.Errorf("DNSBuckets[0] = %v, want 0.00005 (50µs)", DNSBuckets[0])
	}

	// Verify maximum covers slow AXFR (10s)
	if DNSBuckets[len(DNSBuckets)-1] != 10.0 {
		t.Errorf("DNSBuckets last = %v, want 10.0", DNSBuckets[len(DNSBuckets)-1])
	}

	// Verify buckets are monotonically increasing
	for i := 1; i < len(DNSBuckets); i++ {
		if DNSBuckets[i] <= DNSBuckets[i-1] {
			t.Errorf("DNSBuckets not monotonically increasing at index %d: %v <= %v", i, DNSBuckets[i], DNSBuckets[i-1])
		}
	}
}

func TestRecordCacheHitMiss(t *testing.T) {
	// Save original values
	origHit := cacheHitCount.Load()
	origMiss := cacheMissCount.Load()

	// Reset for test
	cacheHitCount.Store(0)
	cacheMissCount.Store(0)

	RecordCacheHit()
	RecordCacheHit()
	RecordCacheMiss()

	if cacheHitCount.Load() != 2 {
		t.Errorf("cacheHitCount = %d, want 2", cacheHitCount.Load())
	}
	if cacheMissCount.Load() != 1 {
		t.Errorf("cacheMissCount = %d, want 1", cacheMissCount.Load())
	}

	// Restore
	cacheHitCount.Store(origHit)
	cacheMissCount.Store(origMiss)
}

func TestDerivedMetricCollector(t *testing.T) {
	// Save and reset
	origHit := cacheHitCount.Load()
	origMiss := cacheMissCount.Load()
	cacheHitCount.Store(0)
	cacheMissCount.Store(0)

	// Simulate 80% hit rate
	cacheHitCount.Store(80)
	cacheMissCount.Store(20)

	collector := NewDerivedMetricCollector(50 * time.Millisecond)
	collector.compute()

	// Restore
	cacheHitCount.Store(origHit)
	cacheMissCount.Store(origMiss)
	collector.Stop()
}

func TestDerivedMetricCollector_Stop(t *testing.T) {
	collector := NewDerivedMetricCollector(time.Hour)
	collector.Stop()
	// Should not hang or panic
}

// mockZoneRecordRepo is a mock implementation of ZoneRecordRepo for testing.
type mockZoneRecordRepo struct {
	zones   []domain.Zone
	records map[string][]domain.Record // keyed by zoneID
}

func (m *mockZoneRecordRepo) ListZones(_ context.Context, _ string) ([]domain.Zone, error) {
	return m.zones, nil
}

func (m *mockZoneRecordRepo) ListRecordsForZone(_ context.Context, zoneID string, _ string) ([]domain.Record, error) {
	if recs, ok := m.records[zoneID]; ok {
		return recs, nil
	}
	return nil, nil
}

func TestZoneRecordCounter(t *testing.T) {
	repo := &mockZoneRecordRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
			{ID: "z2", Name: "test.com."},
		},
		records: map[string][]domain.Record{
			"z1": {
				{ID: "r1", ZoneID: "z1", Name: "www.example.com.", Type: "A"},
				{ID: "r2", ZoneID: "z1", Name: "www.example.com.", Type: "AAAA"},
			},
			"z2": {
				{ID: "r3", ZoneID: "z2", Name: "test.com.", Type: "MX"},
			},
		},
	}

	counter := NewZoneRecordCounter(repo, 50*time.Millisecond)
	ctx := context.Background()

	counter.Start(ctx)

	// Let it collect at least once
	time.Sleep(100 * time.Millisecond)
	counter.Stop()
	// Should not hang or panic
}

func TestZoneRecordCounter_EmptyZones(t *testing.T) {
	repo := &mockZoneRecordRepo{
		zones:   []domain.Zone{},
		records: map[string][]domain.Record{},
	}

	counter := NewZoneRecordCounter(repo, 50*time.Millisecond)
	ctx := context.Background()

	counter.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	counter.Stop()
}

func TestZoneRecordCounter_ZonesWithNoRecords(t *testing.T) {
	repo := &mockZoneRecordRepo{
		zones:   []domain.Zone{{ID: "z1", Name: "empty.com."}},
		records: map[string][]domain.Record{}, // no records for z1
	}

	counter := NewZoneRecordCounter(repo, 50*time.Millisecond)
	ctx := context.Background()

	counter.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	counter.Stop()
}
