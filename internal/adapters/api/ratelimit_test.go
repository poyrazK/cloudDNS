package api

import (
	"testing"
	"time"
)

func TestTenantLimiter(t *testing.T) {
	tl := newTenantLimiter(10, 5, 100) // 10 tokens/sec, burst 5, max 100 tenants
	tenant := "tenant-123"

	// Test initial burst
	for i := 0; i < 5; i++ {
		if !tl.Allow(tenant) {
			t.Errorf("Should allow initial burst: request %d", i)
		}
	}

	// Test rate limit after burst exhausted
	if tl.Allow(tenant) {
		t.Errorf("Should block after burst exhausted")
	}

	// Wait for refill
	time.Sleep(200 * time.Millisecond) // Should refill ~2 tokens
	if !tl.Allow(tenant) {
		t.Errorf("Should allow request after refill")
	}
}

func TestTenantLimiter_Isolation(t *testing.T) {
	tl := newTenantLimiter(10, 1, 100)
	t1 := "tenant-1"
	t2 := "tenant-2"

	// tenant-1 exhausts its burst of 1
	if !tl.Allow(t1) {
		t.Error("Should allow t1")
	}
	if tl.Allow(t1) {
		t.Error("Should block t1 after burst")
	}

	// tenant-2 is independent and has its own burst
	if !tl.Allow(t2) {
		t.Error("Should allow t2 (independent from t1)")
	}
}

func TestTenantLimiter_MaxTenants(t *testing.T) {
	// Create limiter with max 3 tenants
	tl := newTenantLimiter(10, 1, 3)

	// Add 3 different tenants
	for i := 0; i < 3; i++ {
		tenant := "tenant-" + string(rune('A'+i))
		if !tl.Allow(tenant) {
			t.Errorf("Should allow tenant %s", tenant)
		}
	}

	// 4th tenant should trigger eviction
	tl.Allow("tenant-D")

	tl.mu.Lock()
	bucketCount := len(tl.buckets)
	tl.mu.Unlock()

	if bucketCount != 3 {
		t.Errorf("Expected 3 buckets after eviction, got %d", bucketCount)
	}
}