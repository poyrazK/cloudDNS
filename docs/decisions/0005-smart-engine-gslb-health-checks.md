# ADR 0005: Smart Engine & GSLB with Active Health Checks

## Status
Accepted

## Context
Standard DNS servers return static records regardless of the availability of the underlying endpoints. To provide high availability and traffic management (GSLB) capabilities, CloudDNS needs to automatically detect endpoint failures and remove unhealthy records from DNS responses.

## Decision
We have implemented a "Smart Engine" capability that integrates active health monitoring with the DNS resolution logic.

### Key Components

1.  **Extended Record Metadata**:
    *   Added `health_check_type` (NONE, HTTP, TCP) and `health_check_target` to the DNS records.
    *   This allows per-record configuration of how an endpoint should be monitored.

2.  **Health monitoring Service**:
    *   A background worker (`HealthMonitor`) periodically scans the database for records requiring health checks.
    *   It performs HTTP GET or TCP handshake probes against the configured targets.
    *   Probe results are persisted in a dedicated `record_health` table to avoid write contention on the main `dns_records` table and to maintain historical state.

3.  **Context-Aware Probing**:
    *   The `HealthCheck` logic is designed to be "patient" but safe. If the node is under extreme CPU pressure (detected via context deadline), intensive pings are skipped to ensure the system remains responsive to management probes.

4.  **Health-Filtered Resolution**:
    *   The `DNSService.Resolve` logic now filters the candidate records returned by the repository.
    *   Records marked as `UNHEALTHY` are excluded from the DNS response.
    *   **Fallback Mechanism**: If *all* records for a specific query are unhealthy, the engine returns all of them. This avoids a "total blackout" scenario where a DNS query might return `NXDOMAIN` or an empty result just because the monitoring agent is having issues or the entire cluster is failing.

## Consequences
*   **Availability**: Users are automatically steered away from failed endpoints.
*   **Observability**: Real-time health status is now visible via the management API.
*   **Performance**: There is a minor overhead in the `Resolve` function for filtering, but since health data is joined in the repository query, the impact is negligible.
*   **Complexity**: Operators must now ensure the DNS server has network egress to the targets it is monitoring.
