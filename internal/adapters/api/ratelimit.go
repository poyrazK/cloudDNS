package api

import (
	"sync"
	"time"
)

// endpointCategory classifies operations for rate limiting.
type endpointCategory int

const (
	categoryRead endpointCategory = iota
	categoryWrite
	categoryDeleteZone
	categoryDeleteRecord
)

// tokenBucket implements token bucket algorithm.
type tokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   int
	maxKeys int
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newTokenBucket creates a new token bucket limiter.
func newTokenBucket(rate float64, burst int, maxKeys int) *tokenBucket {
	return &tokenBucket{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		maxKeys: maxKeys,
	}
}

// Allow checks if a request should be allowed for the given key.
func (tb *tokenBucket) Allow(key string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	b, exists := tb.buckets[key]
	if !exists {
		if len(tb.buckets) >= tb.maxKeys {
			tb.evictIdleBucket()
		}
		b = &bucket{tokens: float64(tb.burst), last: time.Now()}
		tb.buckets[key] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now

	b.tokens += elapsed * tb.rate
	if b.tokens > float64(tb.burst) {
		b.tokens = float64(tb.burst)
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// evictIdleBucket removes a bucket that hasn't been used recently.
func (tb *tokenBucket) evictIdleBucket() {
	now := time.Now()
	for id, b := range tb.buckets {
		if now.Sub(b.last) > 1*time.Minute {
			delete(tb.buckets, id)
			return
		}
	}
	// If all are active recently, just evict the first one
	for id := range tb.buckets {
		delete(tb.buckets, id)
		return
	}
}

// multiLimiter holds separate limiters per operation category and per IP/tenant.
type multiLimiter struct {
	tenantRead     *tokenBucket
	tenantWrite    *tokenBucket
	tenantDeleteZone *tokenBucket
	tenantDeleteRecord *tokenBucket
	ipRead        *tokenBucket
	ipWrite       *tokenBucket
}

// newMultiLimiter creates a multi-limiter with separate buckets per category.
func newMultiLimiter() *multiLimiter {
	return &multiLimiter{
		tenantRead:        newTokenBucket(1000, 500, 100000),
		tenantWrite:       newTokenBucket(100, 200, 100000),
		tenantDeleteZone:  newTokenBucket(10, 5, 100000),
		tenantDeleteRecord: newTokenBucket(50, 20, 100000),
		ipRead:           newTokenBucket(500, 250, 1000000),
		ipWrite:          newTokenBucket(50, 25, 1000000),
	}
}

// Allow checks if an operation should be allowed for the given tenant/IP/category.
// Returns true if allowed under both IP and tenant limits.
func (ml *multiLimiter) Allow(tenantID, ip string, cat endpointCategory) bool {
	// Check IP limit first
	if !ml.ipLimiterFor(cat).Allow(ip) {
		return false
	}
	// Then check tenant limit
	return ml.tenantLimiterFor(cat).Allow(tenantID)
}

// tenantLimiterFor returns the tenant token bucket for the given category.
func (ml *multiLimiter) tenantLimiterFor(cat endpointCategory) *tokenBucket {
	switch cat {
	case categoryRead:
		return ml.tenantRead
	case categoryWrite:
		return ml.tenantWrite
	case categoryDeleteZone:
		return ml.tenantDeleteZone
	case categoryDeleteRecord:
		return ml.tenantDeleteRecord
	default:
		return ml.tenantWrite
	}
}

// ipLimiterFor returns the IP token bucket for the given category.
func (ml *multiLimiter) ipLimiterFor(cat endpointCategory) *tokenBucket {
	switch cat {
	case categoryRead:
		return ml.ipRead
	case categoryWrite, categoryDeleteZone, categoryDeleteRecord:
		return ml.ipWrite
	default:
		return ml.ipWrite
	}
}
