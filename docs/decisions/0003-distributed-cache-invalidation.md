# ADR 0003: Distributed Cache Invalidation

## Status
Accepted

## Context
When record updates occur via the REST API or Dynamic Updates (RFC 2136), they must be reflected immediately across all nodes in a distributed deployment. Each node maintains a high-performance L1 in-memory cache, which becomes stale if not invalidated.

## Decision
We implement a two-tier caching and invalidation strategy:

1.  **L1 Cache**: Sharded, thread-safe in-memory cache on each node for sub-millisecond response times.
2.  **L2 Cache**: Distributed Redis cache for shared state between nodes.
3.  **Invalidation Mechanism**:
    -   Use **Redis Pub/Sub** for cross-node notifications.
    -   When a record is created or deleted, the node performing the change publishes a message (`name:type`) to a global channel.
    -   All nodes (including the initiator) listen to this channel and invalidate the corresponding key in their local L1 cache.
4.  **Resilience**:
    -   Listeners use a server-scoped context for clean lifecycle management.
    -   Parsing is resilient to malformed payloads.

## Consequences
- **Pros**:
    - Near-instant global consistency for DNS updates.
    - Reduced database load through high L1/L2 hit rates.
    - Standardized interface via `CacheInvalidator` port.
- **Cons**:
    - Dependency on Redis availability for global invalidation (falls back to TTL expiration if Redis is down).
    - Slight overhead for Pub/Sub message processing on every update.
