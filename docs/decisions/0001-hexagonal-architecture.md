# ADR 0001: Hexagonal Architecture (Ports and Adapters)

## Status
Accepted

## Context
The project requires a maintainable and testable structure that allows swapping external dependencies (like databases or cache layers) without affecting the core DNS logic. DNS standards are complex, and the business logic must be isolated from infrastructure concerns.

## Decision
We implement a strict Hexagonal Architecture (Ports & Adapters):

1.  **Core (internal/core/domain)**: Contains pure data structures and DNS logic (e.g., validation rules).
2.  **Ports (internal/core/ports)**: Interfaces that define the input and output requirements of the core.
3.  **Services (internal/core/services)**: Orchestrate business logic by implementing core interfaces or using ports to interact with the outside world.
4.  **Adapters (internal/adapters)**: Concrete implementations of ports.
    -   **Driving Adapters**: DNS Server, REST API.
    -   **Driven Adapters**: PostgreSQL Repository, Redis Cache, BGP Routing Engine.

## Consequences
- **Pros**:
    - High testability: Core logic can be tested using mocks for all ports.
    - Flexibility: Switching from PostgreSQL to another database only requires a new adapter implementation.
    - Separation of Concerns: Infrastructure details (SQL queries, Redis protocol) don't leak into DNS logic.
- **Cons**:
    - Increased boilerplate (interfaces, DTO mappings).
    - Slightly higher learning curve for new contributors.
