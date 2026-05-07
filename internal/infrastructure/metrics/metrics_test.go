package metrics

import (
	"testing"
	"time"
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
