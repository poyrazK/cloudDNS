package server

import (
	"sync"
	"time"
)

// rateLimiter implements a simple per-IP token bucket
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      float64 // tokens per second
	burst     int     // max tokens
	maxBuckets int   // maximum buckets to store (bounds memory)
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate float64, burst int, maxBuckets int) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*bucket),
		rate:      rate,
		burst:     burst,
		maxBuckets: maxBuckets,
	}
}

func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, exists := rl.buckets[ip]
	if !exists {
		// Evict an idle bucket if at capacity
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictIdleBucket()
		}
		b = &bucket{
			tokens: float64(rl.burst),
			last:   time.Now(),
		}
		rl.buckets[ip] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now

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

	return false
}

// evictIdleBucket removes a bucket that hasn't been used recently.
// Returns the IP of the evicted bucket, or "" if none could be evicted.
func (rl *rateLimiter) evictIdleBucket() string {
	now := time.Now()
	for ip, b := range rl.buckets {
		if now.Sub(b.last) > 1*time.Minute {
			delete(rl.buckets, ip)
			return ip
		}
	}
	// If all are active recently, just evict a random one
	for ip := range rl.buckets {
		delete(rl.buckets, ip)
		return ip
	}
	return ""
}

// Cleanup removes old buckets to prevent memory leaks.
func (rl *rateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, b := range rl.buckets {
		if now.Sub(b.last) > 10*time.Minute {
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
