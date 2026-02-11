# cloudDNS Features & Services

A high-performance, authoritative and recursive DNS server built from scratch in Go, designed for modern cloud environments.

## 1. Core DNS Engine (Manual RFC 1035)
Unlike standard implementations that use libraries, cloudDNS implements the binary wire format manually for maximum control and performance.
*   **Manual Binary Parsing**: Custom bit-masking and byte-buffer management for DNS headers, questions, and records.
*   **Supported Record Types**: 
    *   `A` (IPv4) & `AAAA` (IPv6)
    *   `CNAME` (Canonical Name)
    *   `NS` (Name Server)
    *   `MX` (Mail Exchange)
    *   `SOA` (Start of Authority)
    *   `TXT` (Text records)
    *   `OPT` (EDNS pseudo-record)
*   **Label Compression**: Full support for domain name pointers (offsets) during packet deserialization.

## 2. Multi-Transport Server
*   **UDP Support**: High-speed resolution for standard queries.
*   **TCP Support**: Full implementation of DNS-over-TCP with 2-byte length framing, essential for large responses.
*   **Parallel Listeners**: Concurrent handling of both protocols on the same port.

## 3. Advanced Resolution Logic
*   **Recursive Resolver**: A "serious" iterative resolver that can walk the global internet hierarchy starting from root hints (`a.root-servers.net`) when a local record is missing.
*   **Split-Horizon DNS**: Context-aware resolution. The server detects the client's source IP and filters records based on CIDR blocks (Private vs. Public views).
*   **EDNS(0) & Truncation**:
    *   Negotiates UDP payload sizes with clients.
    *   Automatically enforces truncation (`TC` bit) if a response exceeds the negotiated limit, forcing a safe TCP fallback.

## 4. High-Performance Architecture
*   **UDP Worker Pool**: Uses a fixed pool of background workers and a task queue to handle traffic bursts without resource exhaustion.
*   **In-Memory Packet Cache**: A thread-safe, TTL-aware cache that stores serialized binary responses to bypass database lookups for frequent queries.
*   **Hexagonal Architecture**: Strict separation between Domain logic, Ports (Interfaces), and Adapters (PostgreSQL, DNS, API).
*   **Transactional Zone Creation**: Atomic initialization of zones with standard-compliant SOA and NS records.

## 5. Management & Observability
*   **RESTful Management API**: Provides standard HTTP endpoints for multi-tenant Zone and Record management.
*   **PostgreSQL Persistence**: Uses a robust SQL backend for long-term storage of DNS metadata.
*   **Structured JSON Logging**: Powered by `log/slog`. Every query is logged with:
    *   Client IP & Transport (UDP/TCP)
    *   Query Name & Type
    *   Response Code (RCODE)
    *   Cache Status (Hit/Miss)
    *   Processing Latency (µs/ms)

## 6. Stability & Verification
*   **Comprehensive Test Suite**:
    *   **Unit Tests**: Deep coverage of binary serialization and buffer edge cases.
    *   **Integration Tests**: Verified concurrency and cache synchronization.
    *   **E2E Tests**: Full "API-to-Wire" verification (Creating a record via REST and resolving it via real UDP).
