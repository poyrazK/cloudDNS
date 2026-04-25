package server

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(10, 5, 100) // 10 tokens/sec, burst 5, max 100 buckets
	ip := "1.2.3.4"

	// 1. Initial burst
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Should allow initial burst: request %d", i)
		}
	}

	// 2. Should be blocked
	if rl.Allow(ip) {
		t.Errorf("Should block request after burst")
	}

	// 3. Wait for refill
	time.Sleep(200 * time.Millisecond) // Should refill ~2 tokens
	if !rl.Allow(ip) {
		t.Errorf("Should allow request after refill")
	}
}

func TestRateLimiter_Isolation(t *testing.T) {
	rl := newRateLimiter(10, 1, 100)
	ip1 := "1.1.1.1"
	ip2 := "2.2.2.2"

	if !rl.Allow(ip1) {
		t.Errorf("Should allow ip1")
	}
	if rl.Allow(ip1) {
		t.Errorf("Should block ip1")
	}

	if !rl.Allow(ip2) {
		t.Errorf("Should allow ip2 (isolated from ip1)")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := newRateLimiter(10, 5, 100)
	rl.Allow("old.ip")

	// Force old timestamp
	rl.mu.Lock()
	rl.buckets["old.ip"].last = time.Now().Add(-20 * time.Minute)
	rl.mu.Unlock()

	rl.Cleanup()

	rl.mu.Lock()
	_, exists := rl.buckets["old.ip"]
	rl.mu.Unlock()

	if exists {
		t.Errorf("Old bucket should have been cleaned up")
	}
}

func TestRateLimiter_MaxBuckets(t *testing.T) {
	// Create limiter with max 5 buckets
	rl := newRateLimiter(10, 1, 5)

	// Add 5 different IPs
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("1.2.3.%d", i)
		if !rl.Allow(ip) {
			t.Errorf("Should allow IP %s", ip)
		}
	}

	rl.mu.Lock()
	bucketCount := len(rl.buckets)
	rl.mu.Unlock()

	if bucketCount != 5 {
		t.Errorf("Expected 5 buckets, got %d", bucketCount)
	}

	// Backdate one bucket to force idle eviction path
	rl.mu.Lock()
	rl.buckets["1.2.3.0"].last = time.Now().Add(-2 * time.Minute)
	rl.mu.Unlock()

	// 6th IP should evict the backdated idle bucket
	rl.Allow("new.ip")

	rl.mu.Lock()
	_, exists0 := rl.buckets["1.2.3.0"]
	_, exists4 := rl.buckets["1.2.3.4"]
	bucketCount = len(rl.buckets)
	rl.mu.Unlock()

	if exists0 {
		t.Errorf("Idle bucket 1.2.3.0 should have been evicted")
	}
	// Last recently-used bucket should remain
	if !exists4 {
		t.Errorf("Recently used bucket 1.2.3.4 should still exist")
	}
	if bucketCount != 5 {
		t.Errorf("Should still have 5 buckets after eviction, got %d", bucketCount)
	}
}
