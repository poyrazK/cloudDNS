package server

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// BenchmarkRateLimiter_Sharded benchmarks the sharded rate limiter.
func BenchmarkRateLimiter_Sharded(b *testing.B) {
	rl := newRateLimiter(100000, 1, 1000000)
	ips := make([]string, 10000)
	for i := range ips {
		ips[i] = fmt.Sprintf("1.2.%d.%d", i/256, i%256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(ips[i%len(ips)])
	}
}

// singleMutexRateLimiter is the original single-mutex implementation for baseline comparison.
type singleMutexRateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*singleBucket
	rate       float64
	burst      int
	maxBuckets int
	idleHeap   singleBucketIdleHeap
	rateLimited uint64
}

type singleBucket struct {
	tokens  float64
	last   int64 // UnixNano for faster access
	heapIdx int
}

type singleBucketIdleEntry struct {
	ip string
	b  *singleBucket
}

type singleBucketIdleHeap []*singleBucketIdleEntry

func (h singleBucketIdleHeap) Len() int            { return len(h) }
func (h singleBucketIdleHeap) Less(i, j int) bool   { return h[i].b.last < h[j].b.last }
func (h singleBucketIdleHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *singleBucketIdleHeap) Push(x any)         { *h = append(*h, x.(*singleBucketIdleEntry)) }
func (h *singleBucketIdleHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func newSingleMutexRateLimiter(rate float64, burst int, maxBuckets int) *singleMutexRateLimiter {
	h := singleBucketIdleHeap{}
	return &singleMutexRateLimiter{
		buckets:    make(map[string]*singleBucket),
		rate:       rate,
		burst:      burst,
		maxBuckets: maxBuckets,
		idleHeap:   h,
	}
}

func (rl *singleMutexRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UnixNano()
	b, exists := rl.buckets[ip]
	if !exists {
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictOldestBucket()
		}
		b = &singleBucket{tokens: float64(rl.burst), last: now}
		entry := &singleBucketIdleEntry{ip: ip, b: b}
		rl.idleHeap = append(rl.idleHeap, entry)
		b.heapIdx = len(rl.idleHeap) - 1
		rl.buckets[ip] = b
	}

	elapsed := float64(now-b.last) / 1e9
	b.last = now
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	rl.rateLimited++
	return false
}

func (rl *singleMutexRateLimiter) evictOldestBucket() {
	for len(rl.idleHeap) > 0 {
		entry := rl.idleHeap[0]
		rl.idleHeap = rl.idleHeap[1:]
		if entry == nil {
			continue
		}
		if _, ok := rl.buckets[entry.ip]; ok {
			delete(rl.buckets, entry.ip)
			return
		}
	}
}

func (rl *singleMutexRateLimiter) RateLimited() uint64 {
	return uint64(rl.rateLimited)
}

func BenchmarkRateLimiter_SingleMutex(b *testing.B) {
	rl := newSingleMutexRateLimiter(100000, 1, 1000000)
	ips := make([]string, 10000)
	for i := range ips {
		ips[i] = fmt.Sprintf("1.2.%d.%d", i/256, i%256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(ips[i%len(ips)])
	}
}
