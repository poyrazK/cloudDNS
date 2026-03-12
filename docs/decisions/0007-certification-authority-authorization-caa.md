# ADR 0007: Certification Authority Authorization (CAA) Support

## Status
Accepted

## Context
Certificates are a critical part of web security. RFC 6844 defines the Certification Authority Authorization (CAA) DNS Resource Record, which allows domain name holders to specify one or more Certification Authorities (CAs) authorized to issue certificates for that domain.

Supporting CAA records is essential for a modern DNS provider to enhance security and prevent unauthorized certificate issuance.

## Decision
We will implement support for CAA records (Type 257) across the entire cloudDNS stack.

### Implementation Details
1.  **Domain Model**: Add `TypeCAA` to the domain record types.
2.  **Packet Parser**:
    *   Implement wire-format parsing and serialization for CAA records.
    *   CAA records contain a Flag (1 byte), a Tag (string), and a Value (string).
    *   The `QueryType.String()` method will return "CAA" for type 257.
3.  **Repository**:
    *   Store CAA data in the existing `content` field of the `dns_records` table.
    *   The serialization format in the database will be `[flag] [tag] "[value]"`.
    *   Update converters to bridge between the domain model and packet records.
4.  **Server Engine**:
    *   Ensure the resolution engine correctly handles CAA queries.
    *   Include CAA in the automated smoke test suite in CI.

## Consequences
*   Users can now manage CAA records via the API and dynamic updates (RFC 2136).
*   Enhanced security for tenants by allowing them to restrict certificate issuance.
*   The system is now compliant with RFC 6844.
*   Minimal impact on performance as CAA lookups follow the same path as other record types.
