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

// RateLimitConfig holds configuration for rate limiting.
type RateLimitConfig struct {
	// Tenant limits
	TenantReadRate           float64
	TenantReadBurst          int
	TenantWriteRate          float64
	TenantWriteBurst         int
	TenantDeleteZoneRate     float64
	TenantDeleteZoneBurst    int
	TenantDeleteRecordRate   float64
	TenantDeleteRecordBurst int
	// IP limits
	IPReadRate    float64
	IPReadBurst   int
	IPWriteRate   float64
	IPWriteBurst  int
	// Bounds
	MaxTenants int
	MaxIPs     int
}

// DefaultRateLimitConfig returns the default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		TenantReadRate:           1000,
		TenantReadBurst:          500,
		TenantWriteRate:          100,
		TenantWriteBurst:         200,
		TenantDeleteZoneRate:     10,
		TenantDeleteZoneBurst:    5,
		TenantDeleteRecordRate:   50,
		TenantDeleteRecordBurst:  20,
		IPReadRate:               500,
		IPReadBurst:               250,
		IPWriteRate:              50,
		IPWriteBurst:             25,
		MaxTenants:               100000,
		MaxIPs:                  1000000,
	}
}

// tokenBucket implements token bucket algorithm.
type tokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   int
	maxKeys int
}

type bucket struct {
	tokens  float64
	last    time.Time
	lastSeen time.Time // for deterministic eviction
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

	now := time.Now()
	b, exists := tb.buckets[key]
	if !exists {
		if len(tb.buckets) >= tb.maxKeys {
			tb.evictOldestBucket()
		}
		b = &bucket{tokens: float64(tb.burst), last: now, lastSeen: now}
		tb.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.lastSeen = now

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

// evictOldestBucket removes the bucket with the oldest lastSeen timestamp.
func (tb *tokenBucket) evictOldestBucket() {
	oldestID := ""
	oldestTime := time.Now().Add(time.Hour) // far future
	for id, b := range tb.buckets {
		if b.lastSeen.Before(oldestTime) {
			oldestTime = b.lastSeen
			oldestID = id
		}
	}
	if oldestID != "" {
		delete(tb.buckets, oldestID)
	}
}

// multiLimiter holds separate limiters per operation category and per IP/tenant.
type multiLimiter struct {
	tenantRead         *tokenBucket
	tenantWrite        *tokenBucket
	tenantDeleteZone  *tokenBucket
	tenantDeleteRecord *tokenBucket
	ipRead            *tokenBucket
	ipWrite           *tokenBucket
}

// newMultiLimiter creates a multi-limiter with separate buckets per category.
func newMultiLimiter() *multiLimiter {
	return newMultiLimiterWithConfig(DefaultRateLimitConfig())
}

// newMultiLimiterWithConfig creates a multi-limiter with custom configuration.
func newMultiLimiterWithConfig(cfg RateLimitConfig) *multiLimiter {
	return &multiLimiter{
		tenantRead:         newTokenBucket(cfg.TenantReadRate, cfg.TenantReadBurst, cfg.MaxTenants),
		tenantWrite:        newTokenBucket(cfg.TenantWriteRate, cfg.TenantWriteBurst, cfg.MaxTenants),
		tenantDeleteZone:  newTokenBucket(cfg.TenantDeleteZoneRate, cfg.TenantDeleteZoneBurst, cfg.MaxTenants),
		tenantDeleteRecord: newTokenBucket(cfg.TenantDeleteRecordRate, cfg.TenantDeleteRecordBurst, cfg.MaxTenants),
		ipRead:            newTokenBucket(cfg.IPReadRate, cfg.IPReadBurst, cfg.MaxIPs),
		ipWrite:           newTokenBucket(cfg.IPWriteRate, cfg.IPWriteBurst, cfg.MaxIPs),
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
