# cloudDNS - Claude Code Context

## Project Overview

**cloudDNS** is a high-performance, authoritative and recursive DNS server written in Go (1.26.1). It implements strict RFC standards with DNSSEC signing/validation, BGP anycast integration, multi-layer caching (L1 in-memory + L2 Redis), DNS over HTTPS (DoH), IXFR zone transfers, and a REST API for management.

## Architecture

### Hexagonal (Ports & Adapters) Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     cmd/ (Entry Points)                      │
├─────────────────────────────────────────────────────────────┤
│                  internal/adapters/api/                      │
│              (REST API HTTP handlers)                        │
├─────────────────────────────────────────────────────────────┤
│                  internal/core/                              │
│  ┌─────────┬──────────┬─────────┬──────────┬───────────┐   │
│  │ domain/ │ services/ │  ports/ │  config/ │   utils/   │   │
│  │ (ents)  │  (biz log)│ (ifaces)│  (cfg)   │  (util)    │   │
│  └─────────┴──────────┴─────────┴──────────┴───────────┘   │
├─────────────────────────────────────────────────────────────┤
│                  internal/dns/                               │
│  ┌─────────┬──────────┬─────────┬──────────┐               │
│  │ packet/ │  server/ │ master/ │  cache/  │               │
│  │ (wire)  │  (impl)  │ (xfr)   │  (l1/l2) │               │
│  └─────────┴──────────┴─────────┴──────────┘               │
├─────────────────────────────────────────────────────────────┤
│               internal/adapters/repository/                 │
│              (PostgreSQL implementations)                    │
├─────────────────────────────────────────────────────────────┤
│               internal/adapters/routing/                     │
│                    (GoBGP integration)                       │
└─────────────────────────────────────────────────────────────┘
```

## Key Packages

### `cmd/clouddns/` - Main DNS server
- Entry point: `cmd/clouddns/main.go`
- Server configured via environment variables (no config files)

### `internal/dns/server/` - DNS protocol implementation
- **server.go** (~2100 lines): Core `Server` struct handling UDP/TCP/DoT/DoH
- **cache.go**: L1 (sharded in-memory) and L2 (Redis) caching
- **recursive.go**: Iterative recursive resolution with root hints
- **ratelimit.go**: Token bucket rate limiting (500k req/s, burst 200k)

### `internal/dns/packet/` - DNS wire format
- `DNSPacket` struct: Header, Questions, Answers, Authorities, Resources
- Supports all record types: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, SRV, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3, IXFR, AXFR, OPT, TSIG
- EDNS0 support: NSID, Cookie, Padding, EDE (RFC 8914)

### `internal/core/domain/` - Domain entities
- `Zone`: id, name, role (master/slave), vpcid
- `Record`: id, zoneid, name, type, content, ttl, priority/weight/port for MX/SRV
- `UpdateOperation`: ADD, DELETE_RRSET, DELETE_ALL, DELETE_SPECIFIC
- `ZoneChange`: audit trail for zone changes

### `internal/core/services/` - Business logic (10 subdirectories)
- DNSSEC signing and validation
- Recursive resolution
- Zone transfers (AXFR/IXFR)
- Dynamic updates (RFC 2136)

### `internal/adapters/repository/` - PostgreSQL implementations
- Implements `ports.DNSRepository` interface

## Configuration

All configuration via environment variables:
- `DATABASE_URL` - PostgreSQL (default: `postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable`)
- `REDIS_URL` - Redis cache
- `DNS_ADDR` - DNS bind address (default: `127.0.0.1:10053`)
- `API_ADDR` - Management API bind (default: `:8080`)
- `LOG_LEVEL`, `LOG_FORMAT`
- `DNSSEC_MODE` - `disabled`, `ad-bit-only`, `strict`
- `ANYCAST_*` / `BGP_*` - Anycast/BGP configuration
- `TRUST_ANCHOR_<zone>` - Base64-encoded DNSSEC trust anchors

## Build & Deploy

### Build
- `go build -o clouddns-bin cmd/clouddns/main.go`
- Docker multi-stage: `golang:1.26-alpine` builder → `alpine:3.20` runtime
- Statically linked with `CGO_ENABLED=0`

### Test
```bash
go test -short -timeout 5m ./...
go test -v -timeout 10m -coverprofile=coverage.txt $(go list ./... | grep -v "top1m-import")
```
- Coverage threshold: 80% minimum

### Deploy
- ~~GitHub Actions: lint → test → build → push to GCP Artifact Registry → GKE deployment~~
- **Note:** GKE deployment is disabled — we outgrew the gcloud subscription and no longer use deploy workflows
- Ports: 1053/udp, 1053/tcp, 8080/tcp, 853/tcp (Note: uses 1053 instead of privileged 53)

## Query Flow

1. Rate limit check
2. Parse packet (`request.FromBuffer()`)
3. Cache check (L1 → L2)
4. EDNS0 processing
5. Zone lookup (traverse domain labels)
6. Record resolution (direct or wildcard)
7. NXDOMAIN → SOA + NSEC/NSEC3 proofs if DNSSEC
8. Recursive fallback (if `RecursionEnabled` and RD bit set)
9. DNSSEC signing (if DO bit set)
10. DNSSEC validation (if validator configured)
11. Padding (RFC 7830/8467)
12. Truncation (if response > maxSize)
13. Cache result
14. Send response

## Important Files

- `internal/dns/server/server.go` - Main server implementation
- `internal/dns/packet/packet.go` - DNS packet parsing
- `internal/dns/server/cache.go` - Multi-layer cache
- `internal/dns/server/recursive.go` - Recursive resolver
- `internal/core/ports/ports.go` - Repository interface definition
- `internal/core/domain/dns.go` - Domain entities
- `infra/k8s/deployment.yaml` - Kubernetes deployment
- `.github/workflows/go.yml` - CI pipeline

## Documentation

- `README.md` - Project overview
- `features.md` - Feature list
- `docs/dnssec.md` - DNSSEC documentation
- `docs/decisions/` - Architecture Decision Records (ADRs)

## Design Decisions (ADRs)

1. **0001** - Hexagonal architecture
2. **0002** - Anycast/BGP integration
3. **0003** - Distributed cache invalidation
4. **0004** - API authentication and RBAC
5. **0005** - Smart engine GSLB health checks
6. **0006** - Incremental zone transfer (IXFR)
7. **0007** - CAA record support
8. **0008** - DNSSEC validation
9. **0009** - Multi-algorithm DNSSEC