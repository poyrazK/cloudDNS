# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cloudDNS is a high-performance, authoritative and recursive DNS server written in Go (1.26.1). It implements strict RFC standards with DNSSEC signing/validation, BGP anycast integration, multi-layer caching (L1 in-memory + L2 Redis), DNS over HTTPS (DoH), IXFR zone transfers, and a REST API for management.

## Architecture

cloudDNS follows a strict **Hexagonal (Ports & Adapters)** architecture:

```text
cmd/                    # Entry points
├── clouddns/           # Main DNS server
├── apikey/             # API key management CLI
├── bench/              # Benchmark tool
└── iana-*/             # IANA data import tools

internal/
├── adapters/           # Primary (driving) and secondary (driven) adapters
│   ├── api/            # REST API HTTP handlers
│   ├── repository/     # PostgreSQL implementation of ports.DNSRepository
│   └── routing/        # GoBGP integration for anycast
├── core/               # Pure business logic, no external dependencies
│   ├── domain/         # Entities: Zone, Record, ZoneChange, DNSSECKey, etc.
│   ├── ports/          # Interface definitions (DNSRepository, DNSService, etc.)
│   ├── services/       # Business logic: DNSSEC signing/validation, health monitoring
│   └── config/         # Configuration structs
├── dns/
│   ├── packet/         # DNS wire format (RFC 1035) - manual binary parser/serializer
│   ├── server/         # DNS protocol implementation (UDP/TCP/DoT/DoH/DoQ)
│   └── master/         # Zone transfer parsers (AXFR/IXFR)
└── infrastructure/
    └── metrics/        # Prometheus metrics
```

## Key Packages

### `internal/dns/packet/` - DNS Wire Format
- `packet.go`: Core `DNSPacket` struct with Header, Questions, Answers, Authorities, Extra sections
- `buffer.go`: Wire-format binary parser/serializer using a cursor-based Read/Write interface
- `dnssec.go`, `dnssec_verify.go`: DNSSEC record types (DNSKEY, RRSIG, DS, NSEC, NSEC3)
- `tsig.go`: TSIG HMAC authentication (RFC 2845)
- Supports all record types: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3, IXFR, AXFR, OPT, TSIG, HTTPS (RFC 9460)

### `internal/dns/server/` - DNS Protocol Implementation
- **server.go** (~1381 lines): Core `Server` struct handling all transport protocols
- **types.go**: Package-level types (cacheLockShard, TsigKey, inflightEntry, etc.)
- **helpers.go**: Package-level functions (fnv32, lockKey, extractClientIP, parentZoneName, etc.)
- **dnssec.go**: DNSSEC signing, validation, and trust chain building
- **axfr.go**: AXFR/IXFR zone transfer handling
- **update.go**: Dynamic update (RFC 2136) and NOTIFY (RFC 1996) handling
- **nsec.go**: NSEC/NSEC3 record generation for DNSSEC proofs
- **cache.go**: L1 sharded in-memory cache with per-key locking; L2 Redis cache with Pub/Sub invalidation
- **recursive.go**: Iterative recursive resolution using root hints
- **ratelimit.go**: Token bucket rate limiting (500k req/s, burst 200k per client IP)
- **client.go**: Upstream DNS client for recursive resolution
- **doq.go**: DNS-over-QUIC implementation

### `internal/core/domain/` - Domain Entities
- `Zone`: id, name, role (master/slave), vpcid, master_server
- `Record`: id, zoneid, name, type, content, ttl, priority/weight/port for MX/SRV, network (CIDR for split-horizon)
- `UpdateOperation`: ADD, DELETE_RRSET, DELETE_ALL, DELETE_SPECIFIC
- `ZoneChange`: audit trail for zone changes (used for IXFR)
- `IXFRChunk`: serial + deleted/added records for incremental transfer

### `internal/core/ports/` - Interface Definitions
- `DNSRepository`: Full CRUD for zones, records, keys, API keys, audit logs, IXFR chain
- `DNSService`: Business operations (CreateZone, Resolve, ImportZone, etc.)
- `CacheInvalidator`: Cross-node cache invalidation via Redis Pub/Sub
- `RoutingEngine`: BGP route advertisement via GoBGP

### `internal/core/services/` - Business Logic
- `dns_service.go`: Zone/record management, resolution logic
- `dnssec_service.go`: KSK/ZSK key generation, zone signing, Double-Signature rollover
- `dnssec_validator.go`: DNSSEC response validation (multi-algorithm: ECDSA P-256/P-384, Ed25519, Ed448, RSA SHA-256)
- `health_monitor.go`: Smart Engine (GSLB) active health checking (HTTP/TCP)
- `anycast_manager.go`: BGP anycast VIP management

### `internal/adapters/repository/` - PostgreSQL Implementation
- `postgres.go`: Full `DNSRepository` implementation using pgx/v5
- Uses `RecordIterator` interface for streaming large record sets (AXFR/IXFR)

## Query Flow (server.go hot path)

1. **Rate limit check** - Token bucket per client IP
2. **Parse packet** - `request.FromBuffer()` from `internal/dns/packet/`
3. **Cache check** - L1 (sharded in-memory) → L2 (Redis) with singleflight + inflight tracking to prevent thundering herd
4. **EDNS0 processing** - NSID, Cookie, Padding, EDE (RFC 8914)
5. **Zone lookup** - Longest-match domain traversal via `GetZoneLongestMatch()`
6. **Record resolution** - Direct match or wildcard expansion
7. **NXDOMAIN proof** - SOA + NSEC/NSEC3 if DNSSEC enabled
8. **Recursive fallback** - If `RecursionEnabled` and RD bit set, use `recursive.go`
9. **DNSSEC signing** - If DO bit set and zone has keys
10. **DNSSEC validation** - If validator configured and response is DNSSEC
11. **Padding** - RFC 7830/8467 EDNS0 padding
12. **Truncation** - TCP fallback if response > maxSize (typically 1232 for DoH)
13. **Cache result** - Write to L1/L2 with appropriate TTL
14. **Send response** - Return via same transport (UDP/TCP/DoT/DoH/DoQ)

## Configuration

All configuration via environment variables (no config files):

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | `postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable` |
| `REDIS_URL` | Redis connection for L2 cache | - |
| `DNS_ADDR` | DNS bind address | `127.0.0.1:1053` |
| `API_ADDR` | REST API bind | `:8080` |
| `DNSSEC_MODE` | `disabled`, `ad-bit-only`, `strict` | `disabled` |
| `ANYCAST_ENABLED` | Enable BGP anycast | `false` |
| `ANYCAST_VIP` | Virtual IP to announce | - |
| `BGP_PEER_IP` | BGP peer address | - |
| `NODE_ID` | Unique node identity | hostname |
| `TRUST_ANCHOR_<zone>` | Base64 DNSSEC trust anchor | - |

## Build & Test

```bash
# Build
go build -o clouddns-bin cmd/clouddns/main.go

# Run all tests (short mode, ~5 min timeout)
go test -short -timeout 5m ./...

# Run tests with coverage
go test -v -timeout 10m -coverprofile=coverage.txt $(go list ./... | grep -v "top1m-import")

# Run a single test file
go test -v -run TestName ./internal/dns/server/

# Run benchmark suite
go test -bench=. ./cmd/bench/...

# Lint
golangci-lint run
```

Minimum coverage threshold: **80%**

## Important Implementation Patterns

### Sharded Cache Locking (cache.go)
Per-key locking uses 256 shards with FNV-1a hashing to avoid unbounded map growth while providing fine-grained control:

```go
const cacheLockShardCount = 256
func (t *cacheLockTable) lockKey(key string) *cacheLockShard {
    return &t[fnv32(key)%cacheLockShardCount]
}
```

### Thundering Herd Prevention (server.go)
L2 cache fetches use `singleflight.Group` plus an explicit `inflightCache` sync.Map to coalesce concurrent requests for the same key:

```go
inflightCache sync.Map  // Key -> *inflightEntry{done chan struct{}}
querySingleflight singleflight.Group
```

### Streaming Record Iteration (ports.go)
Large record sets (for AXFR/IXFR) use a `RecordIterator` interface to stream without full materialization:

```go
type RecordIterator interface {
    Next() bool
    Err() error
    Record() domain.Record
    Close() error
}
```

## Entry Points

- `cmd/clouddns/main.go` - Main DNS server with all transports
- `cmd/apikey/main.go` - API key CRUD (`create`, `list`, `delete` subcommands)
- `cmd/bench/main.go` - DNS benchmark tool
- `cmd/iana-import/main.go` - Import IANA DNS registry data

## Ports

- DNS: 1053/udp, 1053/tcp (default, uses non-privileged port)
- API: 8080/tcp
- DoT: 853/tcp (if enabled)
- DoH: 8080/tcp via `/dns-query` path (if enabled)
- DoQ: 853/udp (if enabled)

## Documentation

- `docs/dnssec.md` - DNSSEC implementation details
- `docs/decisions/` - Architecture Decision Records (ADRs)
- `features.md` - Full feature list
- `ixfr-plan.md` - IXFR implementation plan