# cloudDNS Features & Services

A high-performance, authoritative and recursive DNS server built from scratch in Go, designed for modern cloud environments.

## 1. Core DNS Engine (Manual RFC 1035)
Unlike standard implementations that rely on generic libraries, cloudDNS uses a custom-built packet parser and serializer for maximum control and efficiency.
*   **Wire Format Mastery**: Full support for A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, and PTR record types.
*   **EDNS(0) Support**: Handles extended DNS payloads and flags.
*   **CHAOS Class**: Support for `id.server.` and `hostname.bind.` queries for node identification.

## 2. Distributed Caching & Invalidation
A sharded, multi-layer caching architecture ensures sub-millisecond response times at scale.
*   **L1 In-Memory Cache**: High-speed, thread-safe sharded cache with Transaction ID rewriting.
*   **L2 Redis Integration**: Shared distributed cache for cross-node performance consistency.
*   **Global Invalidation**: Uses Redis Pub/Sub to trigger real-time cache purges across all replicas when records change.

## 3. High Availability & Anycast
Built-in orchestration for global Anycast networks using BGP.
*   **Native BGP Speaker**: Integration with GoBGP for route announcements.
*   **VIP Management**: Automated aliasing of Anycast VIPs on local network interfaces.
*   **Health-Aware Routing**: Real-time route announcement and withdrawal based on service health.

## 4. Smart Engine (GSLB)
*   **Active Health Monitoring**: Periodically probes record endpoints via HTTP or TCP handshake.
*   **Automated Failover**: Dynamically removes unhealthy records from DNS responses.
*   **Zero-Blackout Fallback**: If all endpoints are unhealthy, the engine returns all records to avoid total service outage.
*   **Historical Tracking**: Maintains a record of health check results and error messages for debugging.

## 5. Advanced DNS Standards
*   **DNSSEC**: Automated Key (KSK/ZSK) management, signing, and Double-Signature rollover.
*   **DoH (DNS over HTTPS)**: Privacy-focused resolution over HTTP/2 using both `GET` and `POST`.
*   **Dynamic Updates (RFC 2136)**: Standardized dynamic record management.
*   **IXFR (Incremental Zone Transfer)**: Efficient synchronization between primary and secondary nodes.

## 6. Management & Security
*   **Hexagonal Architecture**: Strict separation between core logic and infrastructure adapters.
*   **RESTful Management API**: Multi-tenant API for zone and record orchestration.
*   **RBAC & Auth**: Role-based access control with SHA-256 hashed API keys.
*   **Audit Logging**: Comprehensive trail of all administrative actions per tenant.
*   **Rate Limiting**: Built-in protection against DoS and abuse.

## 7. Quality & Compliance
*   **End-to-End Testing**: Validated against real PostgreSQL and Redis instances.
*   **High Test Coverage**: Maintains **84%+** statement coverage across the entire codebase.
*   **RFC Compliance**: Rigorous verification against RFC 1034, 1035, 1995, 1996, 2136, 4034, 4035, and 5155.
