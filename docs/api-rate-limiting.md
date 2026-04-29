# API Rate Limiting

The cloudDNS REST API implements per-tenant and per-IP rate limiting to prevent abuse and ensure fair resource allocation across tenants.

## Overview

The API rate limiter uses a **token bucket algorithm** with separate buckets for different operation categories. This provides defense-in-depth: both IP-based and tenant-based limits must pass for a request to proceed.

## Architecture

```
Request → IP Bucket Check → Tenant Bucket Check → Handler
```

If either the IP bucket or tenant bucket is exhausted, the request is rejected with `429 Too Many Requests`.

## Operation Categories

| Category | Operations | Tenant Limit | Tenant Burst | IP Limit | IP Burst |
|----------|------------|-------------|--------------|-----------|----------|
| `categoryRead` | `GET /zones`, `GET /zones/{id}/records`, `GET /audit-logs` | 1000 rps | 500 | 500 rps | 250 |
| `categoryWrite` | `POST /zones`, `POST /zones/{id}/records` | 100 rps | 200 | 50 rps | 25 |
| `categoryDeleteZone` | `DELETE /zones/{id}` | 10 rps | 5 | 50 rps | 25 |
| `categoryDeleteRecord` | `DELETE /zones/{zone_id}/records/{id}` | 50 rps | 20 | 50 rps | 25 |

### Design Rationale

- **DeleteZone is most restrictive (10 rps)**: Accidental or malicious bulk deletions are prevented
- **Read operations have highest limits (1000 rps)**: List operations are expensive on the database
- **IP limits are independent**: Prevents IP spoofing from bypassing tenant limits

## Memory Bounds

Each bucket entry uses approximately 100 bytes. With bounded maps:

| Bucket Type | Max Entries | Max Memory |
|-------------|-------------|------------|
| Tenant buckets | 100,000 | ~10 MB |
| IP buckets | 1,000,000 | ~100 MB |

When capacity is reached, the bucket with the oldest lastSeen timestamp is evicted.

## Implementation

**Files:**
- `internal/adapters/api/ratelimit.go` - Core rate limiter implementation
- `internal/adapters/api/middleware.go` - `RateLimitMiddleware` integration
- `internal/adapters/api/handler.go` - Route registration with category assignment

### Key Types

```go
// endpointCategory classifies operations for rate limiting.
type endpointCategory int

const (
    categoryRead endpointCategory = iota
    categoryWrite
    categoryDeleteZone
    categoryDeleteRecord
)

// tokenBucket implements the token bucket algorithm.
type tokenBucket struct {
    mu      sync.Mutex
    buckets map[string]*bucket
    rate    float64
    burst   int
    maxKeys int
}

// multiLimiter holds separate limiters per operation category.
type multiLimiter struct {
    tenantRead     *tokenBucket
    tenantWrite    *tokenBucket
    tenantDeleteZone *tokenBucket
    tenantDeleteRecord *tokenBucket
    ipRead        *tokenBucket
    ipWrite       *tokenBucket
}
```

### Client IP Extraction

The middleware extracts the client IP in this order:

1. `X-Real-IP` header (set by trusted reverse proxies)
2. `X-Forwarded-For` header first comma-separated value
3. `r.RemoteAddr` (direct connection)

## Configuration

Default limits are compiled into the binary. To modify, change the values in `newMultiLimiter()`:

```go
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
```

## Response Headers

When a request is rate limited, the server returns:

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{"error": "Too Many Requests: rate limit exceeded"}
```

## Monitoring

Rate limit metrics can be exposed via Prometheus by extending the existing metrics infrastructure. Key observables:

- `rate_limiter_allowed_total{category, tenant}` - Counter of allowed requests
- `rate_limiter_rejected_total{category, tenant}` - Counter of rejected requests
- `rate_limiter_bucket_count{type}` - Current number of active buckets

## See Also

- [ADR 0004: API Authentication and RBAC](decisions/0004-api-authentication-and-rbac.md)
- [Security Documentation](security.md)
