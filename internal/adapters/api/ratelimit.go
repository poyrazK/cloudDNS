package api

import (
	"sync"
	"time"
)

// tenantLimiter implements per-tenant token bucket rate limiting for API writes.
type tenantLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tenantBucket
	rate     float64 // tokens per second per tenant
	burst    int     // max tokens per tenant
	maxTenants int // maximum tenants to track (bounds memory)
}

type tenantBucket struct {
	tokens float64
	last   time.Time
}

// NewTenantLimiter creates a new per-tenant rate limiter.
func NewTenantLimiter(rate float64, burst int, maxTenants int) *tenantLimiter {
	return &tenantLimiter{
		buckets:     make(map[string]*tenantBucket),
		rate:        rate,
		burst:       burst,
		maxTenants: maxTenants,
	}
}

// Allow checks if a write operation should be allowed for the given tenant.
// Returns true if allowed, false if rate limited.
func (tl *tenantLimiter) Allow(tenantID string) bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	b, exists := tl.buckets[tenantID]
	if !exists {
		// Evict an idle bucket if at capacity
		if len(tl.buckets) >= tl.maxTenants {
			tl.evictIdleBucket()
		}
		b = &tenantBucket{
			tokens: float64(tl.burst),
			last:   time.Now(),
		}
		tl.buckets[tenantID] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now

	// Refill
	b.tokens += elapsed * tl.rate
	if b.tokens > float64(tl.burst) {
		b.tokens = float64(tl.burst)
	}

	// Consume
	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

// evictIdleBucket removes a bucket that hasn't been used recently.
func (tl *tenantLimiter) evictIdleBucket() {
	now := time.Now()
	for id, b := range tl.buckets {
		if now.Sub(b.last) > 1*time.Minute {
			delete(tl.buckets, id)
			return
		}
	}
	// If all are active recently, just evict the first one
	for id := range tl.buckets {
		delete(tl.buckets, id)
		return
	}
}