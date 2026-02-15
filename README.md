# cloudDNS

cloudDNS is a high-performance, authoritative, and recursive DNS server built from scratch in Go. Designed for modern cloud environments, it implements strict RFC standards with a focus on security, scalability, and control.

![License](https://img.shields.io/github/license/poyrazK/cloudDNS)
![Go Version](https://img.shields.io/github/go-mod/go-version/poyrazK/cloudDNS)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen)

## Key Features

### Core Protocol & Performance
*   **Manual Wire Format (RFC 1035)**: Custom binary parser and serializer for maximum control over DNS packets.
*   **Dual-Stack Transport**: Parallel high-performance UDP listener pool and framed TCP handlers.
*   **Caching Strategy**: Two-layer caching architecture:
    *   **L1**: In-memory, thread-safe packet cache with Transaction ID rewriting.
    *   **L2**: Distributed Redis cache for scalable deployments.
*   **Worker Pool**: Configurable worker pool pattern to handle high-concurrency traffic bursts.

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

### Architecture & Management
*   **Hexagonal Architecture**: Clean separation of concerns (Domain -> Ports -> Adapters).
*   **PostgreSQL Backend**: Robust persistence for zones, records, and keys.
*   **RESTful API**: Full CRUD API for managing zones, records, and viewing audit logs.
*   **Split-Horizon DNS**: Intelligent resolution providing different answers based on client source IP (CIDR).
*   **Rate Limiting**: Token-bucket based DoS protection per client IP.

## Architecture

cloudDNS follows a strict Hexagonal (Ports & Adapters) architecture:

*   **Core (Domain)**: Pure business logic (DNS packet rules, Zone logic). No external dependencies.
*   **Ports**: Interfaces defining how the core interacts with the outside world (`DNSRepository`, `DNSService`).
*   **Adapters**:
    *   **Primary (Driving)**: DNS Server (UDP/TCP/DoH), REST API (HTTP).
    *   **Secondary (Driven)**: PostgreSQL Repository, Redis Cache.

## Getting Started

### Prerequisites
*   Go 1.21+
*   PostgreSQL
*   Redis (Optional)

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
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_ADDR` | Redis address (host:port) | - |

### Running the Server

```bash
# Export necessary variables
export DATABASE_URL="postgres://user:pass@localhost:5432/clouddns?sslmode=disable"

# Run the server
go run cmd/clouddns/main.go
```

## Testing

cloudDNS maintains a high standard of code quality with **86%+ test coverage**.

```bash
# Run all tests
go test ./...

# Run benchmark suite
go test -bench=. ./cmd/bench/...
```

The test suite includes:
*   **Unit Tests**: Core logic verification.
*   **Integration Tests**: Database interactions using `pgx`.
*   **E2E Tests**: Full server protocol verification (DNSSEC, DoH, AXFR/IXFR) using mock network connections.

## API Usage

### Create a Zone
```bash
curl -X POST http://localhost:8080/zones 
  -H "Content-Type: application/json" 
  -d '{"name": "example.com.", "tenant_id": "admin"}'
```

### Add a Record
```bash
curl -X POST http://localhost:8080/zones/{zone_id}/records 
  -H "Content-Type: application/json" 
  -d '{
    "name": "www.example.com.",
    "type": "A",
    "content": "1.2.3.4",
    "ttl": 300
  }'
```

### DoH Query
```bash
# Base64url encoded query for www.example.com (A)
curl "http://localhost:443/dns-query?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
