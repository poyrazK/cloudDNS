# DNSSEC Validation Roadmap

## Goal
Implement full DNSSEC validation MVP across small, reviewable PRs.

## MVP Scope
- ECDSA P-256 signature verification only (matches existing signing)
- No NSEC3 validation (NSEC for authenticated denial only)
- Manual trust anchor configuration
- AD bit + EDE on failure

---

## PR Roadmap (Ordered for Dependency Chain)

### PR 1: `dnssec-verify-packet` ✅ COMPLETED
**Focus**: Packet-level signature verification functions

**Files**: `internal/dns/packet/dnssec_verify.go`, `dnssec_verify_test.go` (NEW)

**Contents**:
- `VerifyRRSet(rrset []DNSRecord, rrsig DNSRecord, dnskey DNSRecord, now uint32) (bool, error)` - ECDSA P-256 signature verification
- `VerifyDNSKEYMatchesDS(dnskey DNSRecord, ds DNSRecord) (bool, error)` - DNSKEY matches DS record
- `ValidateDNSKEYFormat(dnskey DNSRecord) (bool, error)` - DNSKEY format validation
- `FindMatchingDNSKEY(rrsig DNSRecord, dnskeys []DNSRecord) *DNSRecord` - locate correct DNSKEY for RRSIG
- `extractECDSAPublicKey(dnskey DNSRecord) (*ecdsa.PublicKey, error)` - extract ECDSA key from DNSKEY
- `writeCanonicalRData(r *DNSRecord, buf *BytePacketBuffer) error` - canonical RDATA serialization
- `writeBytes(buf *BytePacketBuffer, data []byte) error` - helper to write byte slice
- Tests for all functions

**Rationale**: Pure functions, no external dependencies, easy to test

**Status**: Merged in `b09e527`, `7a71500`, `dfeec54`

---

### PR 2: `dnssec-validator-service` ✅ COMPLETED
**Focus**: Trust chain validation service

**Files**: `internal/core/services/dnssec_validator.go` (NEW)

**Contents**:
- `DNSSECValidator` struct with trust anchors map
- `ValidateRRSet(rrset, rrsigs, dnskeys) (valid bool, adBit bool, ede *EDE)`
- `ValidateDNSKEYChain(dnskeys, ds, parentDNSKEYs) error`
- `GetTrustAnchor(zone string) *DNSKEY`
- Tests with mocked remote fetches

**Rationale**: Depends on PR1 for verification functions

**Status**: Merged in `d59e189`

---

### PR 3: `dnssec-port-methods` ✅ COMPLETED
**Focus**: Add ports for key fetching

**Files**: `internal/core/ports/` (MODIFY)

**Contents**:
- Add `GetDNSKEYs(ctx context.Context, zone string) ([]DNSRecord, error)` to `DNSRepository` port
- Add `FetchDNSKEYs(ctx context.Context, zone string) ([]DNSRecord, error)` to `RecursiveResolver` port
- Implement in `postgres.go` and `recursive.go`
- Tests for port implementations

**Rationale**: Provides interface for fetching keys from repository/network

**Status**: Merged in `a982a42`

---

### PR 4: `dnssec-server-integration` ✅ COMPLETED
**Focus**: Server integration with AD bit and EDE

**Files**: `internal/dns/server/server.go` (MODIFY)

**Contents**:
- Add `DNSSECValidator` field to `Server` struct
- Add `Validate()` method to `Server`
- Integrate validation in `handlePacket()` after response building
- Set AD bit when valid, SERVFAIL + EDE when invalid
- Add `dnssecMode` config (disabled/ad-bit-only/strict)

**Rationale**: Hooks validation into the packet handling pipeline

**Status**: Merged in `16b4065`, `97901ac`

---

### PR 5: `dnssec-trust-anchors-config` ✅ COMPLETED
**Focus**: Configuration for trust anchors

**Files**: `internal/core/config/dnssec.go` (NEW), `internal/dns/server/server.go` (MODIFY), `cmd/clouddns/main.go` (MODIFY)

**Contents**:
- Add `DNSSECConfig` struct with `TrustAnchors` map and `Mode` string
- Load trust anchors from config/env (`TRUST_ANCHOR_<zone>`, `DNSSEC_MODE`)
- Initialize validator on server startup
- Support multiple trust anchors (root, TLDs)

**Rationale**: Production-ready configuration management

**Status**: Merged in `0b7938c`

---

### PR 6: `dnssec-recursive-keys` ✅ COMPLETED
**Focus**: Fetch DNSKEYs during recursive resolution

**Files**: `internal/dns/server/server.go` (MODIFY)

**Contents**:
- Add `fetchDNSKEYFromNetwork()` method for querying DNSKEY records
- When no trust anchors configured and recursion is enabled, fetch DNSKEYs via recursive resolution
- Convert network-fetched DNSKEYs to domain records for validation

**Rationale**: Enables validation without pre-configured keys for every zone

**Status**: Merged in `8e37d2f`

---

### PR 7: `dnssec-error-handling` ✅ COMPLETED
**Focus**: Comprehensive EDE codes for validation failures

**Files**: `internal/core/services/dnssec_validator.go` (MODIFY)

**Contents**:
- Add RFC 8914 EDE constants (0-18)
- Add `String()` method to EDE for human-readable descriptions
- Update error code mappings:
  - Bogus → EDE 6 (dnssec-bogus)
  - Signature expired → EDE 7 (signature-expired)
  - Missing DNSKEY → EDE 9 (dnskey-missing)
  - Algorithm mismatch → EDE 1 (unsupported-dnskey-algorithm)
- Update tests to reflect new Info strings

**Rationale**: Better debugging for DNSSEC failures with RFC-compliant EDE codes

**Status**: Merged in `feat/dnssec-error-handling` branch

**Status**: Merged in `e493445`, `d630253`

---

### PR 8: `dnssec-integration-tests` ✅ COMPLETED
**Focus**: End-to-end integration tests

**Files**: New integration test files

**Contents**:
- Test against known signed zones (cloudflare.com, isc.org)
- Test AD bit setting on valid responses
- Test SERVFAIL + EDE on invalid signatures
- Test trust anchor configuration
- Test with real recursive resolution

**Rationale**: Validates the full flow works in production-like scenarios

**Status**: Merged in `701561c`

---

## PR Order & Dependencies

```text
PR1 (dnssec-verify-packet)
    ↓
PR2 (dnssec-validator-service)
    ↓
PR3 (dnssec-port-methods) ← PR1 provides types
    ↓
PR4 (dnssec-server-integration) ← Needs PR1, PR2, PR3
    ↓
PR5 (dnssec-trust-anchors-config) ← Needs PR4
    ↓
PR6 (dnssec-recursive-keys) ← Needs PR3
    ↓
PR7 (dnssec-error-handling) ← Can run parallel to PR6
    ↓
PR8 (dnssec-integration-tests) ← Needs all previous
```

## Verification Per PR

```bash
# Each PR should pass:
go test ./... -v
golangci-lint run

# After PR1:
go test ./internal/dns/packet/... -v -run DNSSEC

# After PR2:
go test ./internal/core/services/... -v -run DNSSEC

# After PR8:
# Manual testing with dig
dig @localhost cloudflare.com DNSKEY +do +bufsize=2048
dig @localhost cloudflare.com +dnssec +ad
```
