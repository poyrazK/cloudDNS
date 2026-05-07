package server

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

// rateLimiter implements a simple per-IP token bucket with O(1) eviction.
type rateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	rate       float64 // tokens per second
	burst      int     // max tokens
	maxBuckets int     // maximum buckets to store (bounds memory)
	idleHeap   bucketIdleHeap
	rateLimited atomic.Uint64
}

type bucket struct {
	tokens  float64
	last   time.Time
	heapIdx int // index in idleHeap, -1 if not in heap
}

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
}
func (h *bucketIdleHeap) Push(x any) {
	*h = append(*h, x.(*bucketIdleEntry))
}
func (h *bucketIdleHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// newRateLimiter creates a new rate limiter with the given token rate, burst, and max bucket count.
func newRateLimiter(rate float64, burst int, maxBuckets int) *rateLimiter {
	h := bucketIdleHeap{}
	heap.Init(&h)
	return &rateLimiter{
		buckets:    make(map[string]*bucket),
		rate:       rate,
		burst:      burst,
		maxBuckets: maxBuckets,
		idleHeap:   h,
	}
}

// Allow checks if a request from the given IP is allowed under the token bucket limits.
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[ip]
	if !exists {
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictOldestBucket()
		}
		b = &bucket{
			tokens: float64(rl.burst),
			last:   now,
		}
		entry := &bucketIdleEntry{ip: ip, b: b}
		heap.Push(&rl.idleHeap, entry)
		b.heapIdx = len(rl.idleHeap) - 1
		rl.buckets[ip] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.last = now

	// Update heap position after last change
	heap.Fix(&rl.idleHeap, b.heapIdx)

	// Refill
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}

	// Consume
	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	rl.rateLimited.Add(1)
	metrics.RateLimitedTotal.Inc()
	return false
}

// evictOldestBucket removes the bucket with the oldest last timestamp in O(log n).
func (rl *rateLimiter) evictOldestBucket() {
	for len(rl.idleHeap) > 0 {
		entry := heap.Pop(&rl.idleHeap).(*bucketIdleEntry)
		if entry == nil {
			continue
		}
		// If bucket still exists in map, delete it; otherwise it was already
		// evicted by Cleanup() and this is a stale heap entry — discard it.
		if _, ok := rl.buckets[entry.ip]; ok {
			delete(rl.buckets, entry.ip)
			return
		}
	}
}

// Cleanup removes old buckets to prevent memory leaks.
func (rl *rateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, b := range rl.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			heap.Remove(&rl.idleHeap, b.heapIdx)
			delete(rl.buckets, ip)
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

// RateLimited returns the total number of queries rejected by rate limiting.
func (rl *rateLimiter) RateLimited() uint64 {
	return rl.rateLimited.Load()
}
