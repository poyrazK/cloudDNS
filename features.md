# cloudDNS Features & Services

A high-performance, authoritative and recursive DNS server built from scratch in Go, designed for modern cloud environments.

## 1. Core DNS Engine (Manual RFC 1035)
Unlike standard implementations that use libraries, cloudDNS implements the binary wire format manually for maximum control and performance.
*   **Manual Binary Parsing**: Custom bit-masking and byte-buffer management for DNS headers, questions, and records.
*   **Multi-Transport Support**: Parallel listeners for high-speed **UDP** and framed **TCP** transport.
*   **Label Compression**: Full support for domain name pointers (offsets) during packet deserialization.
*   **Supported Record Types**: `A`, `AAAA`, `CNAME`, `NS`, `MX`, `SOA`, `TXT`, `SRV`, `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`, `OPT` (EDNS), and `TSIG`.

## 2. Advanced Resolution Logic
*   **Recursive Resolver**: A "serious" iterative resolver that walks the global internet hierarchy starting from root hints (`a.root-servers.net`) when a local record is missing.
*   **Split-Horizon DNS**: Context-aware resolution. The server detects the client's source IP and filters records based on CIDR blocks (Private vs. Public views) using the PostgreSQL `<<=` operator.
*   **Wildcard Matching**: Full support for `*.domain.com` patterns with iterative label stripping and response name rewriting.
*   **EDNS(0) & Truncation**:
    *   Negotiates UDP payload sizes up to 65,535 bytes.
    *   Automatically enforces truncation (`TC` bit) if a response exceeds the negotiated limit, forcing safe TCP fallback.
    *   **Extended DNS Errors (RFC 8914)**: Support for granular error codes in OPT records.
*   **Node Identity (CHAOS Class)**: Support for `id.server.` and `hostname.bind.` queries to identify specific nodes in a cluster.

## 3. High Availability & Anycast
*   **Anycast BGP Orchestration**: Native integration with **GoBGP v4**. The server automatically announces its Virtual IP (VIP) to the network core when healthy and withdraws it upon failure.
*   **Automated VIP Management**: Built-in management of local interface IP aliases, ensuring the VIP is bound only when the local node is operational.
*   **Health-Aware Routing**: Intelligent monitoring of Database, Cache, and DNS ports to drive BGP state.

## 4. DNSSEC (RFC 4034/4035/5155)
*   **Automated Key Management**: Background orchestration of KSK (Key Signing Key) and ZSK (Zone Signing Key) generation using ECDSA P-256.
*   **Double-Signature Rollover**: Fully automated, zero-downtime key rotation mechanism.
*   **Dynamic Signing**: Real-time RRSIG generation for authoritative responses.
*   **Authenticated Denial of Existence**: Support for both `NSEC` and `NSEC3` (with salt and iterations) to prevent zone walking.

## 5. Caching & Global Consistency
*   **Distributed Caching**: Shared L2 cache via Redis to reduce backend load across nodes.
*   **Real-Time Invalidation**: Global cache invalidation using Redis Pub/Sub. Administrative changes (API/Dynamic Updates) are broadcast instantly to clear stale L1 entries on all nodes.
*   **Sharded L1 Cache**: High-concurrency sharded memory cache with Transaction ID rewriting for sub-millisecond response times.

## 6. Security & Protection
*   **Rate Limiting**: Built-in **Token Bucket** limiter. Protects the server from UDP floods and DDoS by enforcing per-IP query limits (Default: 200,000 burst / 100,000 sustain).
*   **TSIG (Transaction Signatures)**: HMAC-authenticated DNS transactions for secure Dynamic Updates and Zone Transfers.
*   **DNS over HTTPS (DoH)**: RFC 8484 compliant transport for secure, encrypted resolution over HTTP/2.

## 7. Architecture & Management
*   **Hexagonal Architecture**: Strict separation between Domain logic, Ports (Interfaces), and Adapters (PostgreSQL, Redis, BGP, API).
*   **RESTful Management API**: Multi-tenant CRUD endpoints for Zone and Record management.
*   **API Authentication & RBAC**: Secure access control via SHA-256 hashed API keys and granular roles (`admin`, `reader`), ensuring strict tenant isolation.
*   **Incremental Zone Transfer (IXFR)**: Efficient replication that transfers only serialized changes between masters and slaves.
*   **Audit Trails**: Persistent change logging for every administrative action.

## 8. Stability & Verification
*   **Integration Testing**: Verified against real PostgreSQL and Redis instances.
*   **High Test Coverage**: Maintains **84%+** statement coverage across the entire codebase.
*   **RFC Compliance**: Rigorous verification against RFC 1034, 1035, 1995, 1996, 2136, 4034, 4035, and 5155.
