# cloudDNS Features & Services

A high-performance, authoritative and recursive DNS server built from scratch in Go, designed for modern cloud environments.

## 1. Core DNS Engine (Manual RFC 1035)
Unlike standard implementations that use libraries, cloudDNS implements the binary wire format manually for maximum control and performance.
*   **Manual Binary Parsing**: Custom bit-masking and byte-buffer management for DNS headers, questions, and records.
*   **Multi-Transport Support**: Parallel listeners for high-speed **UDP** and framed **TCP** transport.
*   **Label Compression**: Full support for domain name pointers (offsets) during packet deserialization.
*   **Supported Record Types**: `A`, `AAAA`, `CNAME`, `NS`, `MX`, `SOA`, `TXT`, `OPT` (EDNS), and `TSIG`.

## 2. Advanced Resolution Logic
*   **Recursive Resolver**: A "serious" iterative resolver that walks the global internet hierarchy starting from root hints (`a.root-servers.net`) when a local record is missing.
*   **Split-Horizon DNS**: Context-aware resolution. The server detects the client's source IP and filters records based on CIDR blocks (Private vs. Public views) using the PostgreSQL `<<=` operator.
*   **Wildcard Matching**: Full support for `*.domain.com` patterns with iterative label stripping and response name rewriting.
*   **EDNS(0) & Truncation**:
    *   Negotiates UDP payload sizes up to 65,535 bytes.
    *   Automatically enforces truncation (`TC` bit) if a response exceeds the negotiated limit, forcing safe TCP fallback.
    *   **Extended DNS Errors (RFC 8914)**: Support for granular error codes in OPT records.

## 3. Security & Protection
*   **Rate Limiting**: Built-in **Token Bucket** limiter. Protects the server from UDP floods and DDoS by enforcing per-IP query limits (Default: 100 qps/20 burst).
*   **TSIG (Transaction Signatures)**: Support for HMAC-MD5 authenticated DNS transactions, ensuring requests and responses are signed and verified against shared secrets.
*   **Atomic Transactions**: Zone creation is atomic; default `SOA` and `NS` records are generated and committed in a single PostgreSQL transaction.

## 4. High-Performance Architecture
*   **UDP Worker Pool**: Fixed pool of background workers and a task queue to handle traffic bursts without resource exhaustion.
*   **In-Memory Packet Cache**: Thread-safe, TTL-aware cache that stores serialized binary responses. Includes Transaction ID rewriting to allow sub-millisecond cache hits.
*   **Hexagonal Architecture**: Strict separation between Domain logic, Ports (Interfaces), and Adapters (PostgreSQL, DNS, API).

## 5. Management & Observability
*   **RESTful Management API**: Multi-tenant CRUD endpoints for Zone and Record management.
*   **Health Monitoring**: Dedicated `/health` endpoint verifying end-to-end connectivity including database status.
*   **Audit Trails**: Persistent change logging for every administrative action, tracking "who changed what and when."
*   **Structured JSON Logging**: Powered by `log/slog`. Every query is logged with client IP, latency (ms), cache status, and resolution source.

## 6. Stability & Verification
*   **Integration Testing**: Verified against real PostgreSQL instances using `testcontainers-go`.
*   **High Test Coverage**: 
    *   API: **91.7%**
    *   Core Services: **79.4%**
    *   DNS Protocol: **72.4%**
