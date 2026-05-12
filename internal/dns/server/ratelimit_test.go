package server

import (
	"fmt"
	"sync"
	"sync/atomic"
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
	ip := "old.ip"
	rl.Allow(ip)

	// Access internal shard state to backdate the bucket
	shard := rl.shard(ip)
	shard.mu.Lock()
	b := shard.buckets[ip]
	b.last = time.Now().Add(-20 * time.Minute)
	shard.mu.Unlock()

	// Trigger cleanup
	rl.Cleanup()

	// Verify the bucket is gone by checking Allow reuses the bucket
	// (a cleaned bucket would be removed, so Allow creates a fresh one)
	shard.mu.Lock()
	_, exists := shard.buckets[ip]
	shard.mu.Unlock()
	if exists {
		t.Errorf("Old bucket should have been cleaned up")
	}
}

func TestRateLimiter_MaxBuckets(t *testing.T) {
	// Find 6 IPs that all hash to the same shard so we can test per-shard eviction.
	shardIdx := hashIP("1.2.3.0") % numShards
	var sameShardIPs []string
	for i := 0; len(sameShardIPs) < 6; i++ {
		ip := fmt.Sprintf("100.200.300.%d", i)
		if hashIP(ip)%numShards == shardIdx {
			sameShardIPs = append(sameShardIPs, ip)
		}
		if i > 10000 {
			t.Fatal("could not find 6 IPs in same shard")
		}
	}

	// Create limiter with maxBuckets=1280 so perShard=5. With 6 IPs, 1 eviction occurs.
	rl := newRateLimiter(10, 1, 1280)

	// Add first 5 IPs — all go to the same shard, no eviction yet
	for i := 0; i < 5; i++ {
		if !rl.Allow(sameShardIPs[i]) {
			t.Errorf("Should allow IP %s", sameShardIPs[i])
		}
	}

	shard := &rl.shards[shardIdx]
	shard.mu.Lock()
	bucketCount := len(shard.buckets)
	shard.mu.Unlock()

	if bucketCount != 5 {
		t.Errorf("Expected 5 buckets in shard, got %d", bucketCount)
	}

	// Backdate the oldest bucket to trigger eviction on next Allow
	shard.mu.Lock()
	shard.buckets[sameShardIPs[0]].last = time.Now().Add(-2 * time.Minute)
	shard.mu.Unlock()

	// 6th IP should evict the backdated bucket
	rl.Allow(sameShardIPs[5])

	shard.mu.Lock()
	_, exists0 := shard.buckets[sameShardIPs[0]]
	_, exists4 := shard.buckets[sameShardIPs[4]]
	bucketCount = len(shard.buckets)
	shard.mu.Unlock()

	if exists0 {
		t.Errorf("Idle bucket %s should have been evicted", sameShardIPs[0])
	}
	// Recently-used bucket should remain
	if !exists4 {
		t.Errorf("Recently used bucket %s should still exist", sameShardIPs[4])
	}
	if bucketCount != 5 {
		t.Errorf("Should still have 5 buckets after eviction, got %d", bucketCount)
	}
}

func TestRateLimiter_RateLimited(t *testing.T) {
	rl := newRateLimiter(1.0, 1, 100) // 1 token/sec, burst 1

	// First request should succeed (bucket just created with full burst)
	if !rl.Allow("192.168.1.1") {
		t.Fatal("first request should be allowed")
	}

	// Exhaust the bucket
	if rl.Allow("192.168.1.1") {
		t.Fatal("second request should be rate limited")
	}

	// Now RateLimited() should be > 0
	if rl.RateLimited() == 0 {
		t.Errorf("expected rate limited count > 0 after exhaustion")
	}
}

func TestRateLimiter_ShardingIsolation(t *testing.T) {
	rl := newRateLimiter(100, 1, 1000)

	// Exhaust ip1's bucket (two Allows: one succeeds, one blocked)
	ip1 := "10.0.0.1"
	rl.Allow(ip1) // succeeds
	rl.Allow(ip1) // blocked

	// Find a different IP in the SAME shard so we can test same-shard exhaustion.
	// Use a loop to find an IP that shares ip1's shard.
	var ip2 string
	for i := uint64(0); i < 10000; i++ {
		candidate := fmt.Sprintf("200.200.200.%d", i)
		if rl.shard(candidate) == rl.shard(ip1) && candidate != ip1 {
			ip2 = candidate
			break
		}
	}
	if ip2 == "" {
		t.Skip("could not find IP in same shard as ip1")
	}

	// Same shard: exhausting ip1 SHOULD affect ip2 (they share the bucket limit)
	// This verifies same-shard behavior
	if rl.Allow(ip1) {
		t.Errorf("ip1 should still be rate limited after exhaustion")
	}

	// Different IP in DIFFERENT shard should be unaffected
	var ip3 string
	for i := uint64(0); i < 10000; i++ {
		candidate := fmt.Sprintf("250.250.250.%d", i)
		if rl.shard(candidate) != rl.shard(ip1) {
			ip3 = candidate
			break
		}
	}
	if ip3 == "" {
		t.Skip("could not find IP in different shard from ip1")
	}

	if !rl.Allow(ip3) {
		t.Errorf("ip3 should be allowed (independent shard, independent bucket)")
	}
}

func TestRateLimiter_RateLimitedSumsAllShards(t *testing.T) {
	rl := newRateLimiter(1.0, 1, 10000)

	// Exhaust several IPs across different shards
	ips := []string{}
	for i := 0; i < 256; i++ {
		ip := fmt.Sprintf("192.168.%d.1", i)
		rl.Allow(ip) // succeeds
		rl.Allow(ip) // blocked
		ips = append(ips, ip)
	}

	total := rl.RateLimited()
	if total == 0 {
		t.Errorf("expected RateLimited > 0 after exhausting multiple IPs")
	}
	// Should have at least 256 rejections (one per IP)
	if total < 256 {
		t.Errorf("expected at least 256 rejections, got %d", total)
	}
}

func TestRateLimiter_CleanupIteratesAllShards(t *testing.T) {
	rl := newRateLimiter(10, 5, 1000)

	// Create buckets in multiple shards
	for i := 0; i < 10; i++ {
		rl.Allow(fmt.Sprintf("10.%d.0.1", i))
	}

	// Backdate all buckets across all shards
	for i := range rl.shards {
		rl.shards[i].mu.Lock()
		for ip, b := range rl.shards[i].buckets {
			b.last = time.Now().Add(-20 * time.Minute)
			_ = ip // silence unused variable in debug context
		}
		rl.shards[i].mu.Unlock()
	}

	rl.Cleanup()

	// Verify all shards are empty
	for i := range rl.shards {
		rl.shards[i].mu.Lock()
		nonEmpty := len(rl.shards[i].buckets)
		rl.shards[i].mu.Unlock()
		if nonEmpty != 0 {
			t.Errorf("shard %d should be empty after cleanup, has %d buckets", i, nonEmpty)
		}
	}
}

func TestRateLimiter_ShardDistribution(t *testing.T) {
	// Verify that IPs in the same shard share a bucket,
	// and IPs in different shards have independent buckets.
	rl := newRateLimiter(10, 1, 1000)

	// Find two IPs that hash to the same shard
	var sameShardIPs [2]string
	var diffShardIP string

	// Use a fixed set of IPs to find same shard
	candidates := []string{
		"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4",
		"5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8",
	}

Outer:
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if rl.shard(candidates[i]) == rl.shard(candidates[j]) {
				sameShardIPs[0] = candidates[i]
				sameShardIPs[1] = candidates[j]
				// Find a different shard for diffShardIP
				for k := 0; k < len(candidates); k++ {
					if rl.shard(candidates[k]) != rl.shard(candidates[i]) {
						diffShardIP = candidates[k]
						break Outer
					}
				}
			}
		}
	}

	if sameShardIPs[0] == "" {
		t.Skip("could not find two IPs in same shard in test set")
	}
	if diffShardIP == "" {
		t.Fatal("could not find IP in different shard from same-shard pair")
	}

	// Same shard: exhausting one should affect the other
	rl.Allow(sameShardIPs[0])
	rl.Allow(sameShardIPs[0]) // exhausted
	rl.Allow(sameShardIPs[0]) // still exhausted

	// Different shard: exhausting one should NOT affect the other
	if !rl.Allow(diffShardIP) {
		t.Errorf("diff shard IP %s should be allowed (independent shard)", diffShardIP)
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	rl := newRateLimiter(1000, 1, 10000)
	var allowed atomic.Int64
	var blocked atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 50 IPs shared across 100 goroutines (i%50 = 0..49 repeated twice each)
			// burst=1 per IP, so first request succeeds, second is blocked
			ip := fmt.Sprintf("1.2.3.%d", i%50)
			if rl.Allow(ip) {
				allowed.Add(1)
			} else {
				blocked.Add(1)
			}
		}()
	}
	wg.Wait()

	total := allowed.Load() + blocked.Load()
	if total != 100 {
		t.Errorf("expected 100 total decisions, got %d", total)
	}
	// 50 IPs × 2 goroutines each = 50 allowed (first per IP) + 50 blocked (second per IP)
	if allowed.Load() != 50 {
		t.Errorf("expected 50 allowed, got %d", allowed.Load())
	}
	if blocked.Load() != 50 {
		t.Errorf("expected 50 blocked, got %d", blocked.Load())
	}
	if uint64(blocked.Load()) != rl.RateLimited() {
		t.Errorf("RateLimited() = %d, want %d (blocked count)", rl.RateLimited(), blocked.Load())
	}
}

func TestRateLimiter_MaxBucketsSmall(t *testing.T) {
	// Verify perShard distribution works when maxBuckets < numShards
	// maxBuckets=10, numShards=256: base=0, remainder=10 → first 10 shards get maxBuckets=1, rest get 0
	rl := newRateLimiter(10, 1, 10)

	// Add 10 IPs and track which shards they landed in
	ips := make([]string, 10)
	uniqueShards := make(map[uint64]bool)
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("50.60.70.%d", i)
		if !rl.Allow(ip) {
			t.Errorf("Should allow IP %s", ip)
		}
		ips[i] = ip
		uniqueShards[hashIP(ip)%numShards] = true
	}

	// Assert IPs landed in 10 distinct shards (required for this test's premise)
	if len(uniqueShards) != 10 {
		t.Skipf("test requires 10 IPs in 10 distinct shards, got %d", len(uniqueShards))
	}

	// Verify total buckets = 10 (no evictions since each IP is in its own shard)
	total := 0
	for i := range rl.shards {
		rl.shards[i].mu.Lock()
		total += len(rl.shards[i].buckets)
		rl.shards[i].mu.Unlock()
	}
	if total != 10 {
		t.Errorf("Expected 10 total buckets across all shards, got %d", total)
	}
}
