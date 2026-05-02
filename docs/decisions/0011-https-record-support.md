# ADR 0011: HTTPS Record Type Support

## Status
Accepted

## Context

cloudDNS currently supports A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA, and DNSSEC record types. RFC 9460 defines the HTTPS record type (type 65) which provides service binding hints for HTTP-aware clients. This is increasingly important for modern web infrastructure, especially with HTTP/3 adoption where clients use HTTPS records to discover HTTP/3 support and encrypted client hello (ECH) configurations.

## Decision

We implemented HTTPS record type (RFC 9460) as a new record type in cloudDNS.

### Wire Format

HTTPS records follow the SVCB parameter format (RFC 9460 Section 2):

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  PRIORITY                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                    TARGET                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                  SVCB PARAMETERS              /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

**Priority 0 = AliasMode**: Target is a domain name alias (no SVCB params allowed)
**Priority > 0 = ServiceMode**: Full SVCB parameters

### SVCB Parameters (TLV format)

| Key | Name | Description |
|-----|------|-------------|
| 1 | alpn | ALPN identifiers (e.g., "h3", "h2") |
| 2 | no-default | HTTPS-only hint (no HTTP fallback) |
| 3 | port | Target port (default 443) |
| 5 | echconfig | ECHConfigList (Encrypted Client Hello) |
| 6 | ipv4hint | IPv4 address hints |
| 7 | ipv6hint | IPv6 address hints |

### Implementation

Added to `internal/dns/packet/packet.go`:
- `HTTPS QueryType = 65` constant
- `DNSRecord` struct fields: `HTTPSPriority`, `HTTPSTarget`, `HTTPSAlpn`, `HTTPSEchConfig`, `HTTPSIpv4Hint`, `HTTPSIpv6Hint`, `HTTPSPort`, `HTTPSNoDefault`
- `Read()` case: Parses priority, target, then TLV-encoded SVCB params
- `Write()` case: Serializes priority, target, then TLV-encoded SVCB params

Added to `internal/core/domain/dns.go`:
- `TypeHTTPS RecordType = "HTTPS"`
- `Record` fields: `HTTPSPriority`, `HTTPSHost`, `HTTPSAlpn`, `HTTPSEchConfig`, `HTTPSIpv4Hint`, `HTTPSIpv6Hint`, `HTTPSPort`

Added to `internal/adapters/repository/postgres.go`:
- `ConvertDomainToPacketRecord`: HTTPS → wire format
- `ConvertPacketRecordToDomain`: wire format → HTTPS

Added to `internal/dns/server/server.go`:
- `queryTypeToRecordType()`: HTTPS → TypeHTTPS mapping

## Consequences

### Positive
- HTTPS record queries now work over all transports (UDP, TCP, DoT, DoH, DoQ)
- ECH support enables encrypted DNS for privacy-conscious clients
- HTTP/3 client hints improve performance for modern web infrastructure
- Follows existing record type patterns (SRV-style with dedicated fields)

### Negative
- Additional complexity in packet parsing/serialization
- SVCB parameter parsing adds ~60 lines of code

## Configuration

HTTPS records are created via the REST API like any other record type:

```json
POST /api/v1/zones/{zone_id}/records
{
  "name": "www",
  "type": "HTTPS",
  "ttl": 300,
  "https_priority": 1,
  "https_host": "service.example.com.",
  "https_alpn": "h3,h2",
  "https_port": 443,
  "https_ipv4hint": "192.0.2.1,192.0.2.2",
  "https_ech_config": "base64encodeddata..."
}
```

## References

- [RFC 9460: HTTPS DNS Records](https://datatracker.ietf.org/doc/html/rfc9460)
- [RFC 9461: SVCB HTTPS record semantics](https://datatracker.ietf.org/doc/html/rfc9461)