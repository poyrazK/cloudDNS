# Bugs Report — cloudDNS

## Critical (Would Break Production)

| Issue | Description | Blast Radius |
|-------|-------------|--------------|
| ~~No graceful shutdown~~ **FIXED** | ~~Goroutine leaks - nothing signals cleanup goroutines to stop~~ Now using done channel + WaitGroup tracking for clean exit | ~~OOM on deploy/scale-down~~ Fixed in PR #58 |
| **AXFR/IXFR loads all records into memory** | `ListRecordsForZone` loads entire zone before streaming (lines 496, 1284). 1M record zone = gigabytes allocated | OOM kills on large zone transfers |
| **AXFR/IXFR has no TSIG validation** | Zone transfer requests don't verify TSIG keys - any client gets full zone data | Complete zone exfiltration |
| **Dynamic update partial failure** | SOA serial incremented in memory but if `ApplyZoneUpdate` fails, no rollback (line 1177-1182) | Serial drift, slaves out of sync |

### Details

#### 1. AXFR/IXFR Memory Explosion
**File:** `server.go` (lines 483-567, 1210-1409)

```go
// AXFR - Line 496
records, errList := s.Repo.ListRecordsForZone(ctx, zone.ID, zone.TenantID)

// IXFR Fallback - Line 1284
records, errList := s.Repo.ListRecordsForZone(ctx, zone.ID, zone.TenantID)
```

Both AXFR and IXFR fallback load **ALL records for a zone into memory** before streaming. A zone with 1 million records will allocate gigabytes.

#### 3. AXFR/IXFR No TSIG Authorization
**File:** `server.go` (lines 483-567)

AXFR and IXFR transfer requests do **not** check for TSIG authentication. Any client can request a full zone transfer.

Compare to `handleUpdate` at line 1047 which does validate TSIG:
```go
if request.TSIGStart != -1 {
    tsig := request.Resources[len(request.Resources)-1]
    secret, ok := s.TsigKeys[tsig.Name]
```

#### 4. NOTIFY Handler Goroutine Leak
**File:** `server.go` (lines 1021-1032)

```go
go func(zoneName string) {
    zone, err := s.Repo.GetZone(ctx, zoneName)  // Uses s.lifecycleCtx!
```

The goroutine captures `s.lifecycleCtx` which is set to `context.Background()` at line 115. This context never cancels.

#### 5. Dynamic Update Transaction Failure
**File:** `server.go` (lines 1177-1182)

```go
if errApply := s.Repo.ApplyZoneUpdate(ctx, dbZone.ID, operations, newSerial, changes); errApply != nil {
    // No rollback of serial number
}
```

---

## Security Risks

| Issue | Description |
|-------|-------------|
| **AXFR/IXFR not authenticated** | No TSIG check on transfer requests |
| **API has no rate limiting** | Authenticated attackers can flood zones/records |
| **Audit logs are fire-and-forget** | `s.repo.SaveAuditLog` result is ignored - compliance forensic data lost silently |

### Details

#### AXFR Not Authenticated
The `handleAxfr` function (server.go:483-567) does not check for TSIG keys. Any client can request a full zone transfer, exfiltrating all zone data.

#### API No Rate Limiting
**File:** `handler.go` (lines 26-43)

The REST API handlers have no rate limiting. An authenticated attacker can:
- Create millions of zones
- Create millions of records
- Delete entire zones rapidly

#### Audit Logs Silent Failure
**File:** `dns_service.go` (lines 104-115)

```go
_ = s.repo.SaveAuditLog(ctx, logEntry) // Fire and forget audit for now
```

Audit log failures are silently swallowed. Compliance and security investigations become impossible.

---

## Scalability Issues

| Issue | Description |
|-------|-------------|
| **Zone lookup is N+1** | Up to 5 DB calls per query (one per label in domain name) |
| **Rate limiter map is unbounded** | Each unique IP gets a bucket stored forever - IP spoofing fills memory |
| **Recursive resolution has no total timeout** | Up to 225s blocked per root server failure |
| **GetRecordsToProbe has no pagination** | 10M health-check records loaded into memory at once |
| **Cache invalidation race condition** | No synchronization between invalidation msgs and concurrent cache access |

### Details

#### Zone Lookup N+1
**File:** `server.go` (lines 791-804)

```go
zoneName := q.Name
for {
    z, _ := s.Repo.GetZone(ctx, zoneName)  // DB call per label
    if z != nil {
        zone = z
        break
    }
    zoneName = zoneName[idx+1:]  // next label
}
```

For `foo.bar.baz.example.com`, up to 5 database calls per query.

#### Rate Limiter Unbounded
**File:** `ratelimit.go` (lines 29-58)

```go
func (rl *rateLimiter) Allow(ip string) bool {
    b, exists := rl.buckets[ip]
    if !exists {
        b = &bucket{...}
        rl.buckets[ip] = b  // Never removed
    }
```

Each unique IP gets a bucket stored indefinitely. Under IP spoofing attack, millions of buckets accumulate.

#### Recursive Resolution No Total Timeout
**File:** `recursive.go` (lines 55-167)

The outer loop has **no total timeout**. A malicious/failing root server can cause the resolver to hang for the full 15*5=75 seconds per root, times 3 roots = potentially 225 seconds blocked.

#### GetRecordsToProbe No Pagination
**File:** `postgres.go` (lines 387-429)

```go
func (r *PostgresRepository) GetRecordsToProbe(ctx context.Context) ([]domain.Record, error) {
    query := `SELECT ... FROM dns_records WHERE health_check_type IN ('HTTP', 'TCP')...`
```

10 million health-check records loaded into memory at once.

---

## Bad Decisions

| Issue | Location |
|-------|----------|
| **SOA serial uses unbounded increment** - no overflow check for 32-bit limit | server.go:1117-1121 |
| **IXFR history gap detection is incomplete** - only checks sequential serials but not whether chain starts at `clientSerial+1` | server.go:1267-1276 |
| **CAA regex is brittle** - doesn't handle escaped quotes per RFC 6844 | postgres.go:1244 |
| **Health check deadline logic is backwards** - returns empty results if deadline < 15s | dns_service.go:258-262 |

### Details

#### SOA Serial Overflow
**File:** `server.go` (lines 1117-1121)

```go
newSerial = currentSerial + 1  // No bounds check
```

SOA serial is a 32-bit unsigned integer (RFC 1982). If it reaches 4294967295 and wraps, slaves will reject the zone.

#### IXFR Gap Detection Bug
**File:** `server.go` (lines 1267-1276)

```go
historyValid := len(chunks) > 0 && chunks[0].Serial == clientSerial+1
```

The gap detection only checks for sequential serials but does NOT verify that the first chunk's serial is actually `clientSerial+1` after finding the chunks.

#### CAA Regex Brittle
**File:** `postgres.go` (line 1244)

```go
re := regexp.MustCompile(`^(\d+)\s+([a-zA-Z0-9]+)\s+"(.*)"$`)
```

This regex does not properly handle escaped quotes within CAA values. RFC 6844 allows quoted strings with escaped characters.

#### Health Check Deadline Backwards
**File:** `dns_service.go` (lines 258-262)

```go
if time.Until(deadline) < 15*time.Second {
    s.logger.Warn("skipping health check pings due to tight deadline")
    return res  // Returns empty results!
}
```

This returns empty results if the deadline is less than 15 seconds away. But a 15-second deadline might be intentional.

---

## Silent Failures

| Issue | Location |
|-------|----------|
| Audit log failures swallowed | dns_service.go:115 |
| Redis cache nil panic | server.go:231 |
| IXFR error ignored | server.go:1265 |

### Details

```go
// dns_service.go:115
_ = s.repo.SaveAuditLog(ctx, logEntry) // Fire and forget

// server.go:231 - if s.Cache is nil (Redis-only mode)
s.Cache.Invalidate(l1Key)  // PANIC

// server.go:1265 - error from GetIXFRChain ignored
chunks, err := s.Repo.GetIXFRChain(ctx, zone.ID, clientSerial)
```

---

## Operational Gaps

- No health check endpoint for the DNS server itself
- No graceful shutdown sequence
- No structured logging (uses raw `s.Logger`)
- No dead letter queue for failed pub/sub messages

---

## Verdict

**[x] High Risk** — Significant production concerns:
- Goroutine leaks will crash on every deployment
- AXFR has no authentication (critical security vulnerability)
- Zone lookup N+1 will saturate DB under high QPS
- Rate limiter unbounded map enables memory exhaustion attacks
- Recursive resolution can block for minutes under upstream failures

**Medium Risk:**
- Dynamic update partial failure causes serial drift
- Audit log silent failures break compliance
- IXFR gap detection bug causes incomplete transfers
- API lacks rate limiting

**Low Risk:**
- DNSSEC only supports ECDSA P-256 (interoperability)
- Health check deadline logic backwards