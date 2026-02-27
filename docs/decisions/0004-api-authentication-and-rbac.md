# ADR 0004: API Authentication and Role-Based Access Control (RBAC)

## Status
Accepted

## Context
The CloudDNS management API was initially implemented with a hardcoded `default-tenant` and no authentication. To support real-world multi-tenancy and secure administrative operations, the system requires a robust authentication and authorization mechanism.

## Decision
We have implemented a Bearer token-based authentication system with Role-Based Access Control (RBAC).

### Key Components

1.  **API Keys**:
    *   API keys are generated as 32-character random strings with a `cdns_` prefix.
    *   To ensure security, only the **SHA-256 hash** of the key is stored in the database.
    *   Each key is associated with a `tenant_id`, a `role`, and an `expiration_date`.
    *   A `key_prefix` (first 8 characters) is stored in plain text to allow users to identify their keys without exposing the full secret.

2.  **Authentication Middleware**:
    *   Extracts the Bearer token from the `Authorization` header.
    *   Hashes the token and looks up the corresponding record in the `api_keys` table.
    *   Validates that the key is `active` and not `expired`.
    *   Injects the `TenantID` and `Role` into the request `context.Context` for use by downstream handlers.

3.  **Role-Based Access Control (RBAC)**:
    *   We define two primary roles:
        *   `admin`: Full CRUD access to all resources within the tenant's scope.
        *   `reader`: Read-only access to zones, records, and audit logs.
    *   A `RequireRole` middleware enforces these permissions at the route level.

4.  **CLI Management Tool**:
    *   A dedicated CLI tool (`cmd/apikey`) is provided for bootstrapping and ongoing key management.
    *   Supports `create`, `list`, and `revoke` operations.

## Consequences
*   **Security**: Raw API keys are never stored, minimizing the impact of a database compromise.
*   **Isolation**: All API requests are strictly scoped to the `tenant_id` associated with the API key.
*   **Complexity**: Adding a new endpoint now requires explicit role assignment in `handler.go`.
*   **Performance**: Each API request now requires a database lookup for the API key. This can be optimized with an L1 cache in the future if needed.
