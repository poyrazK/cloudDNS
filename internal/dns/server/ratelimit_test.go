package server

import (
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(10, 5) // 10 tokens/sec, burst 5
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
	rl := newRateLimiter(10, 1)
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
	rl := newRateLimiter(10, 5)
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
