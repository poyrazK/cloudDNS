package api

import (
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	tb := newTokenBucket(10, 5, 100) // 10 tokens/sec, burst 5, max 100 keys
	key := "test-key"

	// Test initial burst
	for i := 0; i < 5; i++ {
		if !tb.Allow(key) {
			t.Errorf("Should allow initial burst: request %d", i)
		}
	}

	// Test rate limit after burst exhausted
	if tb.Allow(key) {
		t.Errorf("Should block after burst exhausted")
	}

	// Wait for refill
	time.Sleep(200 * time.Millisecond) // Should refill ~2 tokens
	if !tb.Allow(key) {
		t.Errorf("Should allow request after refill")
	}
}

func TestTokenBucket_Isolation(t *testing.T) {
	tb := newTokenBucket(10, 1, 100)
	k1 := "key-1"
	k2 := "key-2"

	// key-1 exhausts its burst of 1
	if !tb.Allow(k1) {
		t.Error("Should allow k1")
	}
	if tb.Allow(k1) {
		t.Error("Should block k1 after burst")
	}

	// key-2 is independent and has its own burst
	if !tb.Allow(k2) {
		t.Error("Should allow k2 (independent from k1)")
	}
}

func TestTokenBucket_MaxKeys(t *testing.T) {
	// Create limiter with max 3 keys
	tb := newTokenBucket(10, 1, 3)

	// Add 3 different keys
	for i := 0; i < 3; i++ {
		key := "key-" + string(rune('A'+i))
		if !tb.Allow(key) {
			t.Errorf("Should allow key %s", key)
		}
	}

	// 4th key should trigger eviction
	tb.Allow("key-D")

	tb.mu.Lock()
	bucketCount := len(tb.buckets)
	tb.mu.Unlock()

	if bucketCount != 3 {
		t.Errorf("Expected 3 buckets after eviction, got %d", bucketCount)
	}
}

func TestMultiLimiter_Allow(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip := "192.168.1.1"

	// Should allow read operations
	if !ml.Allow(tenant, ip, categoryRead) {
		t.Error("Should allow read")
	}

	// Should allow write operations
	if !ml.Allow(tenant, ip, categoryWrite) {
		t.Error("Should allow write")
	}

	// Should allow delete zone (more restrictive but still allows)
	if !ml.Allow(tenant, ip, categoryDeleteZone) {
		t.Error("Should allow delete zone")
	}
}

func TestMultiLimiter_CategoryIsolation(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip := "192.168.1.1"

	// Exhaust IP read bucket (limit is 250) - this is hit first in defense-in-depth
	for i := 0; i < 250; i++ {
		ml.Allow(tenant, ip, categoryRead)
	}

	// Write operations should still be allowed (independent bucket: tenantWrite)
	if !ml.Allow(tenant, ip, categoryWrite) {
		t.Error("Write should still be allowed after IP read exhaustion (different bucket)")
	}
}

func TestMultiLimiter_DeleteZoneBurst(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip := "192.168.1.1"

	// DeleteZone burst is 5, exhaust it
	for i := 0; i < 5; i++ {
		if !ml.Allow(tenant, ip, categoryDeleteZone) {
			t.Errorf("Should allow burst request %d", i)
		}
	}

	// Should be blocked on DeleteZone
	if ml.Allow(tenant, ip, categoryDeleteZone) {
		t.Error("DeleteZone should be rate limited after burst")
	}
}

func TestMultiLimiter_DeleteRecordBurst(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip := "192.168.1.1"

	// DeleteRecord burst is 20, exhaust it
	for i := 0; i < 20; i++ {
		if !ml.Allow(tenant, ip, categoryDeleteRecord) {
			t.Errorf("Should allow burst request %d", i)
		}
	}

	// Should be blocked on DeleteRecord
	if ml.Allow(tenant, ip, categoryDeleteRecord) {
		t.Error("DeleteRecord should be rate limited after burst")
	}
}

func TestMultiLimiter_EmptyKeys(t *testing.T) {
	ml := newMultiLimiter()
	ip := "192.168.1.1"
	tenant := "tenant-1"

	// Empty tenant should still work (uses empty string as key)
	if !ml.Allow("", ip, categoryRead) {
		t.Error("Empty tenant should be allowed")
	}

	// Empty IP should still work (uses empty string as key)
	if !ml.Allow(tenant, "", categoryRead) {
		t.Error("Empty IP should be allowed")
	}

	// Both empty should work
	if !ml.Allow("", "", categoryWrite) {
		t.Error("Both empty should be allowed")
	}
}

func TestMultiLimiter_IPIsolation(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// Exhaust ip1 reads (limit is 250)
	for i := 0; i < 250; i++ {
		ml.Allow(tenant, ip1, categoryRead)
	}

	// ip2 reads should still work (independent IP bucket)
	if !ml.Allow(tenant, ip2, categoryRead) {
		t.Error("IP2 should still be allowed after IP1 exhaustion")
	}
}

func TestMultiLimiter_IPCheckedFirst(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip := "192.168.1.1"

	// First exhaust tenant reads (limit is 500)
	for i := 0; i < 500; i++ {
		ml.Allow(tenant, ip, categoryRead)
	}

	// Now exhaust ip reads (limit is 250) - this hits the IP limit first
	for i := 0; i < 250; i++ {
		ml.Allow(tenant, ip, categoryRead)
	}

	// Both exhausted, should be rate limited
	if ml.Allow(tenant, ip, categoryRead) {
		t.Error("Should be rate limited after both buckets exhausted")
	}
}

func TestMultiLimiter_DeleteZoneStricter(t *testing.T) {
	ml := newMultiLimiter()
	tenant := "tenant-1"
	ip := "192.168.1.1"

	// DeleteZone burst is 5, exhaust it
	for i := 0; i < 5; i++ {
		ml.Allow(tenant, ip, categoryDeleteZone)
	}

	// Should be blocked on DeleteZone
	if ml.Allow(tenant, ip, categoryDeleteZone) {
		t.Error("DeleteZone should be rate limited after burst")
	}

	// But Write should still work (different bucket)
	if !ml.Allow(tenant, ip, categoryWrite) {
		t.Error("Write should still be allowed after DeleteZone exhaustion")
	}
}