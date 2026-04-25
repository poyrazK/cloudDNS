# Security

cloudDNS implements multiple layers of protection against abuse and attacks.

## Rate Limiting

The DNS server implements per-IP token bucket rate limiting to prevent DoS attacks.

**Configuration:**
- `rate`: Tokens per second (default: 500,000)
- `burst`: Maximum burst size (default: 200,000)
- `maxBuckets`: Maximum number of tracked IPs (default: 1,000,000)

**Behavior:**
- Each unique source IP gets a token bucket
- Buckets are created on first request from an IP
- When `maxBuckets` is reached, idle buckets (>1 min inactive) are evicted to make room
- The cleanup loop also runs every 5 minutes to remove buckets idle >10 minutes

**Memory bounds:**
- Each bucket uses ~100 bytes
- With `maxBuckets=1,000,000`, rate limiter uses at most ~100MB regardless of attack volume

**Example configuration in server initialization:**
```go
limiter: newRateLimiter(500000, 200000, 1000000),
```

## TSIG Authentication

Zone transfers (AXFR/IXFR) support TSIG authentication as defined in RFC 2845. TSIG keys must be configured in the server's `TsigKeys` map.

## DNSSEC

DNSSEC validation is supported with ECDSA P-256 (NSEC3) signatures. See [dnssec.md](dnssec.md) for details.

## API Authentication

The REST API uses SHA-256 hashed API keys with role-based access control (admin, writer, reader). See [docs/decisions/0004-api-authentication-and-rbac.md](docs/decisions/0004-api-authentication-and-rbac.md).
