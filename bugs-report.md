# Bugs Report — cloudDNS

## Critical (Would Break Production)

| Issue | Description | Blast Radius |
|-------|-------------|--------------|
| ~~No graceful shutdown~~ **FIXED** | ~~Goroutine leaks - nothing signals cleanup goroutines to stop~~ Now using done channel + WaitGroup tracking for clean exit | ~~OOM on deploy/scale-down~~ Fixed in PR #58 |
| ~~AXFR/IXFR loads all records into memory~~ **FIXED** | ~~`ListRecordsForZone` loads entire zone before streaming~~ Now uses streaming `RecordIterator` via `ListRecordsForZoneStreaming` | ~~OOM kills on large zone transfers~~ Fixed in PR #59 |
| ~~AXFR/IXFR has no TSIG validation~~ **FIXED** | ~~Zone transfer requests don't verify TSIG keys~~ TSIG validation added to `handleAXFR` and `handleIXFR` | ~~Complete zone exfiltration~~ Fixed in PR #59 |
| ~~Dynamic update partial failure~~ **FIXED** | ~~SOA serial incremented in memory but if `ApplyZoneUpdate` fails, no rollback~~ Now calculates serial inside `ApplyZoneUpdate` transaction | ~~Serial drift, slaves out of sync~~ Fixed in PR #60 |

### Details

#### 1. AXFR/IXFR Memory Explosion — FIXED
**File:** `server.go` — `handleAXFR`, `handleIXFR`

**Fixed in PR #59** by introducing `RecordIterator` interface with streaming:
```go
// Before (loads all into memory)
records, errList := s.Repo.ListRecordsForZone(ctx, zone.ID, zone.TenantID)

// After (streams via iterator)
iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
defer func() { _ = iter.Close() }()
```

New `postgresRecordIterator` wraps `*sql.Rows` for true streaming — records are fetched row-by-row without loading the full zone into memory.

#### 3. AXFR/IXFR No TSIG Authorization — FIXED
**File:** `server.go` — `handleAXFR`, `handleIXFR`

**Fixed in PR #59** by adding TSIG validation matching `handleUpdate` pattern:
```go
if request.TSIGStart != -1 {
    tsig := request.Resources[len(request.Resources)-1]
    secret, ok := s.TsigKeys[tsig.Name]
    if !ok {
        s.Logger.Warn("AXFR failed: unknown TSIG key", "key", tsig.Name)
        s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
        return
    }
    if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, secret); errVerify != nil {
        s.Logger.Warn("AXFR failed: TSIG verification failed", "error", errVerify)
        s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
        return
    }
}
```

#### 4. NOTIFY Handler Goroutine Leak
**File:** `server.go` (lines 1021-1032)

```go
go func(zoneName string) {
    zone, err := s.Repo.GetZone(ctx, zoneName)  // Uses s.lifecycleCtx!
```

The goroutine captures `s.lifecycleCtx` which is set to `context.Background()` at line 115. This context never cancels.

#### 5. Dynamic Update Transaction Failure — FIXED
**File:** `server.go` (lines 1177-1182)

**Fixed in PR #60** by moving SOA serial calculation into `ApplyZoneUpdate` inside the database transaction. The serial is now calculated and stored atomically with the operations — if the transaction fails, the serial is not advanced.

```go
// Before: serial calculated before transaction
newSerial = currentSerial + 1  // Line 1174
if errApply := s.Repo.ApplyZoneUpdate(ctx, dbZone.ID, operations, newSerial, changes); errApply != nil {

// After: ApplyZoneUpdate fetches SOA serial inside the transaction
newSerial, errApply := s.Repo.ApplyZoneUpdate(ctx, dbZone.ID, operations, changes)
```

---

## Security Risks

| Issue | Description |
|-------|-------------|
| ~~AXFR/IXFR not authenticated~~ **FIXED** | ~~No TSIG check on transfer requests~~ TSIG validation added in PR #59 |
| **API has no rate limiting** | Authenticated attackers can flood zones/records |
| **Audit logs are fire-and-forget** | `s.repo.SaveAuditLog` result is ignored - compliance forensic data lost silently |

### Details

#### AXFR Not Authenticated — FIXED
**File:** `server.go` — `handleAXFR`, `handleIXFR`

**Fixed in PR #59** — Both handlers now validate TSIG keys when `request.TSIGStart != -1`, checking key existence and verifying the HMAC.

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
| **Rate limiter map is unbounded** **FIXED** | ~~Each unique IP gets a bucket stored forever - IP spoofing fills memory~~ Now has maxBuckets limit (1M) with idle eviction when at capacity | ~~Memory exhaustion via IP spoofing~~ Fixed in PR #62 |
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

#### Rate Limiter Unbounded — FIXED
**File:** `ratelimit.go` (lines 29-58)

**Fixed in PR #62** by adding a `maxBuckets` limit with idle eviction:

```go
type rateLimiter struct {
    buckets   map[string]*bucket
    maxBuckets int   // bounds memory usage
}

func (rl *rateLimiter) Allow(ip string) bool {
    b, exists := rl.buckets[ip]
    if !exists {
        if len(rl.buckets) >= rl.maxBuckets {
            rl.evictIdleBucket()  // Remove idle before adding
        }
        b = &bucket{...}
        rl.buckets[ip] = b
    }
```

With `maxBuckets=1,000,000`, memory is bounded at ~100MB regardless of attack.

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

**[x] High Risk** — Significant production concerns (reduced by 2 in PR #59):
- ~~AXFR has no authentication (critical security vulnerability)~~ — Fixed in PR #59
- ~~AXFR/IXFR memory explosion~~ — Fixed in PR #59
- ~~Zone lookup N+1 will saturate DB under high QPS~~ — Fixed in PR #61
- ~~Rate limiter unbounded map enables memory exhaustion attacks~~ — Fixed in PR #62
- Recursive resolution can block for minutes under upstream failures

**Medium Risk:**
- ~~Dynamic update partial failure causes serial drift~~ — Fixed in PR #60
- Audit log silent failures break compliance
- IXFR gap detection bug causes incomplete transfers
- API lacks rate limiting

**Low Risk:**
- DNSSEC only supports ECDSA P-256 (interoperability)
- Health check deadline logic backwards