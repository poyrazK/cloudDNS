# ADR 0008: DNSSEC Validation

## Status
Accepted

## Context

DNSSEC (DNS Security Extensions) adds cryptographic authentication to DNS responses, allowing validators to verify that responses originate from the authoritative DNS server and were not tampered with during transit. RFC 4033-4035 define the DNSSEC protocol.

For a DNS provider to fully support DNSSEC, it must be able to:
1. **Sign zones** (already implemented) - Sign zone data with DNSKEY/KEY records
2. **Validate responses** (this ADR) - Verify signatures on incoming responses before returning them to clients

This ADR documents the DNSSEC validation implementation for cloudDNS.

## Decision

We implement DNSSEC validation with the following architecture:

### 1. Validation Scope (MVP)

- **Algorithm**: ECDSA P-256 (Algorithm 13 / RSASHA256) - matches existing signing
- **Denial of Existence**: NSEC only (no NSEC3 support)
- **Trust Model**: Manual trust anchor configuration
- **Response Bits**: Set AD (Authenticated Data) bit on validated responses
- **Error Reporting**: RFC 8914 Extended DNS Error (EDE) codes on validation failures

### 2. Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Server                                │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │ DNSSECMode  │───▶│   Validator  │───▶│  AD Bit / EDE │  │
│  │   Config    │    │              │    │    Response   │  │
│  └─────────────┘    └──────────────┘    └───────────────┘  │
│                           │                                  │
│         ┌─────────────────┼─────────────────┐               │
│         ▼                 ▼                 ▼               │
│  ┌────────────┐    ┌────────────┐    ┌──────────────┐      │
│  │ Trust      │    │  Packet    │    │  Recursive   │      │
│  │ Anchors    │    │  Verify    │    │  DNSKEY      │      │
│  └────────────┘    └────────────┘    │  Fetch       │      │
│                                       └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### 3. Key Components

#### DNSSECValidator Service (`internal/core/services/dnssec_validator.go`)

```go
type DNSSECValidator struct {
    trustAnchors map[string]packet.DNSRecord // zone -> DNSKEY
}

type ValidationResult struct {
    Valid   bool    // Validation succeeded
    ADBit   bool    // Set in DNS response
    EDE     *EDE    // Extended DNS Error if invalid
}
```

**Methods:**
- `ValidateRRSet(rrset, rrsigs, dnskeys, now)` - Validate RRset with RRSIGs
- `ValidateWithTrustAnchor(zone, rrset, rrsigs, dnskeys, now)` - Validate using trust anchor
- `ValidateDNSKEYChain(dnskeys, ds, parentDNSKEY)` - Validate DNSKEY matches DS record
- `GetTrustAnchor(zone)` - Retrieve configured trust anchor

#### RFC 8914 EDE Codes

Extended DNS Error codes for detailed validation failure reporting:

| Code | Name | Use Case |
|------|------|----------|
| 0 | Other | Unclassified error |
| 1 | UnsupportedDNSKEYAlgo | Algorithm not supported |
| 2 | UnsupportedDSDigest | DS digest type unsupported |
| 4 | Bogus | Signature verification failed |
| 6 | SignatureExpired | Signature expiration passed |
| 7 | SignatureNotYetValid | Signature not yet valid |
| 9 | DNSKEYMissing | Matching DNSKEY not found |
| 17 | TrustAnchorUnknown | Trust anchor not configured |

#### Packet-Level Verification (`internal/dns/packet/dnssec_verify.go`)

- `VerifyRRSet(rrset, rrsig, dnskey, now)` - ECDSA P-256 signature verification
- `FindMatchingDNSKEY(rrsig, dnskeys)` - Locate correct DNSKEY for RRSIG
- `ValidateDNSKEYFormat(dnskey)` - Verify DNSKEY wire format
- `VerifyDNSKEYMatchesDS(dnskey, ds)` - Verify DNSKEY matches DS record

### 4. DNSSEC Modes

The server supports three DNSSEC validation modes:

```go
type DNSSECMode string
const (
    DNSSECModeDisabled    DNSSECMode = "disabled"      // No validation
    DNSSECModeAdBitOnly  DNSSECMode = "ad-bit-only"    // Set AD on validated, no rejection
    DNSSECModeStrict     DNSSECMode = "strict"         // Reject invalid with SERVFAIL + EDE
)
```

### 5. Trust Anchor Configuration

Trust anchors are configured manually:

```yaml
dnssec:
  enabled: true
  mode: strict
  trust_anchors:
    ".": "<root DNSKEY base64>"
    "com.": "<com DNSKEY base64>"
```

### 6. Validation Flow

```
Client Query (DO=1)
        │
        ▼
┌───────────────────┐
│  Build Response   │
│  (with RRSIGs)   │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Fetch DNSKEYs    │◀── From recursive resolution
│  (if not cached)  │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Validate RRSet   │
│  (signature check)│
└────────┬──────────┘
         │
    ┌────┴────┐
    │ Valid?  │
    └────┬────┘
    Yes  │  No
    ┌────┴────┐
    │         │
    ▼         ▼
  AD=1      [Mode]
           Disabled: Return response (AD=0)
           AdBitOnly: Return response (AD=0)
           Strict: SERVFAIL + EDE
```

### 7. Implementation Timeline (PRs)

| PR | Focus | Files |
|----|-------|-------|
| 1 | Packet-level verification | `dnssec_verify.go` |
| 2 | Validator service | `dnssec_validator.go` |
| 3 | Port interfaces | `ports/` |
| 4 | Server integration | `server.go` |
| 5 | Trust anchor config | `config/` |
| 6 | Recursive key fetch | `recursive.go` |
| 7 | EDE codes (RFC 8914) | `dnssec_validator.go` |
| 8 | Integration tests | `dnssec_integration_test.go` |

## Consequences

### Positive
- Clients can verify response authenticity using AD bit
- Detailed error reporting via RFC 8914 EDE codes
- Supports validation of any signed zone with trust anchor
- Incremental implementation via small PRs

### Negative
- Additional latency from signature verification (ECDSA P-256 is fast)
- Cache memory overhead for DNSKEYs
- Complexity in recursive resolution path

### Limitations (MVP)
- No NSEC3 support (only NSEC for authenticated denial)
- No automatic trust anchor bootstrap (manual configuration required)
- No validation of responses from third-party resolvers
- No ECDSA P-384 support (future enhancement)

## Future Enhancements

1. **NSEC3 Support** - For zones using NSEC3 instead of NSEC
2. **Automatic Trust Bootstrap** - Fetch and validate root DNSKEY automatically
3. **Algorithm Expansion** - Add support for ECDSA P-384
4. **DS Validation** - Full chain validation from trust anchor to leaf
5. **DNSSEC Key Rollover Support** - Handle key changes gracefully
