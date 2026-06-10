# ADR 0012: DNS64 Support (RFC 6147)

## Status
Accepted

## Date
2026-06-10

## Context

IPv6-only clients cannot communicate directly with IPv4-only servers. In cloud environments where IPv6 migration is ongoing, many services only have A records (IPv4) but clients may attempt to connect via AAAA queries (IPv6). This creates a connectivity gap.

DNS64 (RFC 6147) bridges this gap by synthesizing AAAA records from existing A records when an IPv6 query returns NODATA. The synthesized address embeds the IPv4 address into a designated IPv6 prefix (Well-Known Prefix `64:ff9b::/96`).

## Decision

Implement DNS64 synthesis in cloudDNS with the following characteristics:

### Configuration
- `DNS64_ENABLED=true` — Enable DNS64 synthesis
- `DNS64_PREFIX=64:ff9b::` — Custom prefix (default: Well-Known Prefix)

### Synthesis Logic
When a query for AAAA returns NODATA (no AAAA records exist, but the zone exists):
1. Query for A records at the same name
2. If A records exist, synthesize AAAA records by embedding each IPv4 into the configured prefix
3. Return synthesized AAAA records with NoError response code

### Prefix Handling
- Default: `64:ff9b::/96` (RFC 6147 Well-Known Prefix)
- IPv4 address `w.x.y.z` becomes `64:ff9b::w.x.y.z`
- Invalid prefixes (IPv4, nil) fall back to default

### Caching
- DNS64 responses use1-second TTL per RFC 6147 Section 5
- Normal caching is bypassed for synthesized responses

### Scope
- DNS64 only applies to authoritative NODATA responses (not recursive resolution)
- DNSSEC signing works normally on synthesized records

## Consequences

### Positive
- IPv6-only clients can communicate with IPv4-only servers without NAT64 hardware
- Transparent to clients — no configuration changes required on the client side
- Improves IPv6 migration path in cloud environments

### Negative
- Additional query processing path for AAAA queries
- Small TTL reduces cache effectiveness for synthesized records

### Neutral
- AAAA queries without A records are unaffected
- Recursive resolution unchanged

## Alternatives Considered

### Alternative 1: NAT64 Hardware at Network Layer
**Why rejected:** Requires dedicated hardware appliance, not software-defined, expensive for distributed deployments.

### Alternative 2: CLient-Side DNS64
**Why rejected:** Requires client configuration changes, not transparent, defeats purpose of centralized DNS server.

## References
- [RFC 6147 - DNS64: DNS Extensions for IPv6 Transition](https://datatracker.ietf.org/doc/html/rfc6147)
- [RFC 6052 - IPv6 Addressing of IPv4/IPv6 Translators](https://datatracker.ietf.org/doc/html/rfc6052) (prefix format)
