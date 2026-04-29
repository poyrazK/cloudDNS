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

	// Exhaust tenant reads
	for i := 0; i < 500; i++ {
		ml.Allow(tenant, ip, categoryRead)
	}

	// Write operations should still be allowed (different bucket)
	if !ml.Allow(tenant, ip, categoryWrite) {
		t.Error("Write should still be allowed after read exhaustion (different bucket)")
	}
}