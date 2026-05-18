package server

import (
	"container/heap"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

const numShards = 256

// rateLimiterShard is an independent rate limiter segment with its own lock and bucket map.
type rateLimiterShard struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	rate        float64 // tokens per second
	burst       int     // max tokens
	maxBuckets  int     // maximum buckets in this shard
	idleHeap    bucketIdleHeap
	rateLimited atomic.Uint64
}

// rateLimiter implements a sharded per-IP token bucket with O(1) eviction per shard.
type rateLimiter struct {
	shards     [numShards]rateLimiterShard
	rate       float64 // tokens per second
	burst      int     // max tokens
	maxBuckets int     // maximum total buckets across all shards
}

type bucket struct {
	tokens  uint64 // tokens encoded as tokens<<10 + frac (scale=1024)
	last    time.Time
	heapIdx int // index in idleHeap, -1 if not in heap
}

const bucketScale = 1024

type bucketIdleEntry struct {
	ip string
	b  *bucket
}

type bucketIdleHeap []*bucketIdleEntry

func (h bucketIdleHeap) Len() int { return len(h) }
func (h bucketIdleHeap) Less(i, j int) bool {
	return h[i].b.last.Before(h[j].b.last)
}
func (h bucketIdleHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].b.heapIdx = i
	h[j].b.heapIdx = j
}
func (h *bucketIdleHeap) Push(x any) {
	*h = append(*h, x.(*bucketIdleEntry))
	(*h)[len(*h)-1].b.heapIdx = len(*h) - 1
}
func (h *bucketIdleHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	item.b.heapIdx = -1
	return item
}

// hashIP returns a uint64 hash of an IP string using FNV32a.
func hashIP(ip string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(ip))
	return h.Sum64()
}

// shard returns the rateLimiterShard for the given IP.
func (rl *rateLimiter) shard(ip string) *rateLimiterShard {
	return &rl.shards[hashIP(ip)%numShards]
}

// newRateLimiter creates a new rate limiter with the given token rate, burst, and max bucket count.
func newRateLimiter(rate float64, burst int, maxBuckets int) *rateLimiter {
	rl := &rateLimiter{
		rate:       rate,
		burst:      burst,
		maxBuckets: maxBuckets,
	}
	// Distribute maxBuckets evenly across shards, giving any remainder to the first shards.
	// This ensures the sum of per-shard caps never exceeds maxBuckets.
	base := maxBuckets / numShards
	remainder := maxBuckets % numShards
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*bucket)
		rl.shards[i].rate = rate
		rl.shards[i].burst = burst
		// First 'remainder' shards get one extra bucket slot.
		if i < remainder {
			rl.shards[i].maxBuckets = base + 1
		} else {
			rl.shards[i].maxBuckets = base
		}
		heap.Init(&rl.shards[i].idleHeap)
	}
	return rl
}

// Allow checks if a request from the given IP is allowed under the token bucket limits.
func (rl *rateLimiter) Allow(ip string) bool {
	shard := rl.shard(ip)
	now := time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	b, exists := shard.buckets[ip]
	if !exists {
		if len(shard.buckets) >= shard.maxBuckets {
			shard.evictOldestBucket()
		}
		b = &bucket{
			tokens: uint64(shard.burst) << 10,
			last:   now,
		}
		entry := &bucketIdleEntry{ip: ip, b: b}
		heap.Push(&shard.idleHeap, entry)
		b.heapIdx = len(shard.idleHeap) - 1
		shard.buckets[ip] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.last = now

	// Update heap position after last change
	heap.Fix(&shard.idleHeap, b.heapIdx)

	// Refill tokens
	b.tokens += uint64(elapsed * shard.rate * bucketScale)
	maxTokens := uint64(shard.burst) << 10
	if b.tokens > maxTokens {
		b.tokens = maxTokens
	}

	allowed := b.tokens >= bucketScale
	if allowed {
		b.tokens -= bucketScale
	}

	if !allowed {
		shard.rateLimited.Add(1)
		metrics.RateLimitedTotal.Inc()
	}
	return allowed
}

// evictOldestBucket removes the bucket with the oldest last timestamp in O(log n) within this shard.
func (sh *rateLimiterShard) evictOldestBucket() {
	for len(sh.idleHeap) > 0 {
		entry := heap.Pop(&sh.idleHeap).(*bucketIdleEntry)
		if entry == nil {
			continue
		}
		// If bucket still exists in map, delete it; otherwise it was already
		// evicted by Cleanup() and this is a stale heap entry — discard it.
		if _, ok := sh.buckets[entry.ip]; ok {
			delete(sh.buckets, entry.ip)
			return
		}
	}
}

// Cleanup removes old buckets from all shards to prevent memory leaks.
func (rl *rateLimiter) Cleanup() {
	for i := range rl.shards {
		rl.shards[i].Cleanup()
	}
}

// Cleanup removes old buckets from this shard.
func (sh *rateLimiterShard) Cleanup() {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	now := time.Now()
	for ip, b := range sh.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			heap.Remove(&sh.idleHeap, b.heapIdx)
			delete(sh.buckets, ip)
		}
	}
}

// CleanupLoop periodically removes old buckets to prevent memory leaks.
// It exits when done is closed.
func (rl *rateLimiter) CleanupLoop(done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			rl.Cleanup()
		}
	}
}

// RateLimited returns the total number of queries rejected by rate limiting across all shards.
func (rl *rateLimiter) RateLimited() uint64 {
	var total uint64
	for i := range rl.shards {
		total += rl.shards[i].rateLimited.Load()
	}
	return total
}
