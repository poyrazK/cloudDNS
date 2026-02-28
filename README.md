# cloudDNS

cloudDNS is a high-performance, authoritative, and recursive DNS server built from scratch in Go. Designed for modern cloud environments, it implements strict RFC standards with a focus on security, scalability, and control.

![License](https://img.shields.io/github/license/poyrazK/cloudDNS)
![Go Version](https://img.shields.io/github/go-mod/go-version/poyrazK/cloudDNS)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-84%2B%25-brightgreen)

## Key Features

### Core Protocol & Performance
*   **Manual Wire Format (RFC 1035)**: Custom binary parser and serializer for maximum control over DNS packets.
*   **Dual-Stack Transport**: Parallel high-performance UDP listener pool and framed TCP handlers.
*   **Caching Strategy**: Sharded, two-layer caching architecture:
    *   **L1**: In-memory, thread-safe sharded cache with Transaction ID rewriting.
    *   **L2**: Distributed Redis cache for shared state.
    *   **Global Invalidation**: Real-time cross-node cache invalidation via Redis Pub/Sub.
*   **Worker Pool**: Configurable worker pool pattern to handle high-concurrency traffic bursts.

### High Availability & Anycast
*   **Anycast BGP Integration**: Native BGP support (GoBGP v4) for sub-second failover orchestration.
*   **Automated VIP Management**: Built-in management of local interface IP aliases for Anycast VIPs.
*   **Health-Aware Routing**: Real-time route announcement and withdrawal based on service health.

### Advanced DNS Standards
*   **Dynamic Updates (RFC 2136)**: Secure, atomic updates to zone records at runtime.
*   **Incremental Zone Transfer (IXFR - RFC 1995)**: Efficient replication that transfers only changes, not the entire zone.
*   **DNS NOTIFY (RFC 1996)**: Real-time notification to secondary servers upon zone changes.
*   **DNSSEC (RFC 4034/4035/5155)**:
    *   **Automated Lifecycle**: Background worker handles Key (KSK/ZSK) generation and rotation.
    *   **Double-Signature Rollover**: Zero-downtime key rotation orchestration.
    *   **NSEC/NSEC3**: Authenticated denial of existence.
*   **DNS over HTTPS (DoH - RFC 8484)**: Secure DNS queries via HTTP/2, supporting both `GET` (base64url) and `POST` (binary).
*   **EDNS(0) & Truncation (RFC 6891)**: Extended payload support with automatic TCP fallback.
*   **TSIG (RFC 2845)**: HMAC-authenticated transactions for secure updates and transfers.
*   **CHAOS Class Support**: Node identity resolution (`id.server.`, `hostname.bind.`) for NSID-ready deployments.

### Architecture & Management
*   **Hexagonal Architecture**: Clean separation of concerns (Domain -> Ports -> Adapters).
*   **PostgreSQL Backend**: Robust persistence for zones, records, and keys.
*   **RESTful API**: Full CRUD API for managing zones, records, and viewing audit logs.
*   **Split-Horizon DNS**: Intelligent resolution providing different answers based on client source IP (CIDR).
*   **API Authentication & RBAC**: Secure RESTful API with SHA-256 hashed API keys and role-based permissions (`admin`, `reader`).
*   **Rate Limiting**: Token-bucket based DoS protection per client IP.

## Architecture

cloudDNS follows a strict Hexagonal (Ports & Adapters) architecture:

*   **Core (Domain)**: Pure business logic (DNS packet rules, Zone logic). No external dependencies.
*   **Ports**: Interfaces defining how the core interacts with the outside world (`DNSRepository`, `DNSService`, `RoutingEngine`).
*   **Adapters**:
    *   **Primary (Driving)**: DNS Server (UDP/TCP/DoH), REST API (HTTP).
    *   **Secondary (Driven)**: PostgreSQL Repository, Redis Cache, BGP Engine.

## Getting Started

### Prerequisites
*   Go 1.24+
*   PostgreSQL 15+
*   Redis 7+ (Optional, for distributed caching)

### Installation

```bash
git clone https://github.com/poyrazK/cloudDNS.git
cd cloudDNS
go mod download
```

### Configuration

The server is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DNS_ADDR` | Address for DNS listener | `:53` |
| `API_ADDR` | Address for REST API | `:8080` |
| `API_TLS_CERT` | TLS certificate path for API | - |
| `API_TLS_KEY` | TLS private key path for API | - |
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `ANYCAST_ENABLED` | Enable BGP Anycast support | `false` |
| `ANYCAST_VIP` | Virtual IP to announce via BGP | - |
| `BGP_PEER_IP` | Upstream BGP peer IP | - |
| `NODE_ID` | Unique identity for this node | (hostname) |

### Running the Server

```bash
# Export necessary variables
export DATABASE_URL="postgres://user:pass@localhost:5432/clouddns?sslmode=disable"

# Run the server
go run cmd/clouddns/main.go
```

### API Key Management

cloudDNS uses API keys for managing zones and records. You can generate a bootstrap admin key using the `apikey` tool:

```bash
# Create an admin key for a tenant
go run cmd/apikey/main.go create -tenant "my-org" -role "admin" -name "Production Key"

# List keys for a tenant
go run cmd/apikey/main.go list -tenant "my-org"
```

All API requests must include the `Authorization: Bearer <key>` header.

## Testing

cloudDNS maintains a high standard of code quality with **84%+ test coverage**.

```bash
# Run all tests
go test ./...

# Run benchmark suite
go test -bench=. ./cmd/bench/...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
