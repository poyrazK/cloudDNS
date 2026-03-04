# ADR 0006: Incremental Zone Transfer (IXFR) via Transactional Delta Logging

## Status
Accepted

## Context
Standard Full Zone Transfer (AXFR - RFC 1035) requires transferring the entire zone data whenever a change occurs. For large zones with high-frequency updates (e.g., dynamic DNS or rapid endpoint failovers), this is inefficient, consumes excessive bandwidth, and increases synchronization latency between Primary and Secondary nodes.

## Decision
We have implemented Incremental Zone Transfer (IXFR - RFC 1995) to allow CloudDNS nodes to synchronize only the specific records that have changed since a particular version.

### Key Components

1.  **Transactional Change Tracking**:
    *   Introduced a `dns_zone_changes` table that records every atomic modification to a zone.
    *   Each entry captures the `ACTION` (ADD/DELETE), the record data, and the `SERIAL` version produced by that change.

2.  **SOA-Bounded Delta Logging**:
    *   To ensure the IXFR stream is perfectly reconstructible, the Dynamic Update (RFC 2136) logic was enhanced to explicitly log the Old SOA as a `DELETE` and the New SOA as an `ADD` for every serial increment.
    *   This allows the Master to easily group changes into chunks bounded by the specific versions requested by the Slave.

3.  **RFC 1995 Compliant Master Stream**:
    *   The Master `handleIXFR` logic fetches the chain of changes between the Slave's current serial and the Master's latest serial.
    *   It streams the data in the standardized IXFR format: `[Current SOA, (Old SOA, Deltas, New SOA)*, Current SOA]`.

4.  **Intelligent AXFR Fallback**:
    *   If requested history is missing or a gap is detected in the change log, the Master automatically switches to an AXFR sequence within the IXFR stream (`[Current SOA, Full Zone, Current SOA]`).
    *   This ensures the Slave can always synchronize, even if it has been offline for a period exceeding the Master's log retention.

5.  **Robust Slave State Machine**:
    *   The Slave `performIXFR` implementation uses a state machine to distinguish between incremental and full transfers.
    *   It applies deletions and additions transactionally to maintain zone consistency during the transfer.

## Consequences
*   **Efficiency**: Dramatically reduces bandwidth and processing overhead for routine zone updates.
*   **Convergence**: Faster propagation of changes across the Anycast network.
*   **Storage**: The `dns_zone_changes` table requires persistent storage. A pruning policy must be implemented to manage the growth of this table.
*   **Complexity**: The Master and Slave logic is more complex than simple AXFR, requiring careful handling of serial arithmetic and state transitions.
