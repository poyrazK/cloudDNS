# ADR 0002: Anycast BGP Integration

## Status
Accepted

## Context
To provide high availability and low latency, DNS servers must be deployable in an Anycast configuration. This requires the server to dynamically announce and withdraw its Virtual IP (VIP) via BGP based on the health of its local services (DNS, Database, Cache).

## Decision
We integrate native BGP support using **GoBGP v4**:

1.  **AnycastManager**: A core service that monitors the health of all registered backends.
2.  **GoBGPAdapter**: A driven adapter that interacts with a local or remote BGP speaker to announce/withdraw routes.
3.  **SystemVIPAdapter**: A driven adapter that manages local system interfaces (e.g., `lo` alias) to bind the Anycast VIP.
4.  **Automatic State Management**:
    -   If all checks pass: Bind VIP -> Announce BGP.
    -   If any check fails: Withdraw BGP -> (Keep VIP bound for local connectivity).
    -   Graceful Shutdown: Withdraw all routes before process exit.

## Consequences
- **Pros**:
    - Sub-second failover orchestration at the network layer.
    - No external health checking agent required (self-healing).
    - Clean integration into hexagonal architecture via `RoutingEngine` and `VIPManager` ports.
- **Cons**:
    - Requires root privileges (for VIP binding) or specific Linux capabilities.
    - Dependency on GoBGP adds complexity to the binary.
    - Testing requires complex mocks or privileged environments.
 Broadway.
