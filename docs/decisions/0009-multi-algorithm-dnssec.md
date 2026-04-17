# ADR 0009: Multi-Algorithm DNSSEC Support

## Status
Accepted

## Context

cloudDNS implemented ECDSA P-256 (Algorithm 13) DNSSEC signing and validation as its initial algorithm. However, RSA SHA-256 (Algorithm 8) and Ed25519 (Algorithm 15) are widely deployed in production DNS infrastructure, particularly for compatibility with older resolvers and compliance requirements.

Adding multi-algorithm support required changes across the entire DNSSEC stack:

1. **Signing** (`SignRRSet`) - Accept algorithm parameter and switch between RSA PKCS#1 v1.5, ECDSA, and Ed25519 signing
2. **Verification** (`VerifyRRSet`) - Handle all three algorithms with separate key extraction paths
3. **Key Generation** (`GenerateKey`) - Support multiple algorithm types with appropriate key sizes
4. **Call sites** - Update all callers of `SignRRSet` to pass the algorithm parameter

## Decision

We chose a phased approach that kept PRs small and reviewable:

### Phase 1: Algorithm Constants

Added algorithm constants to `internal/dns/packet/dnssec.go`:

```go
const (
    AlgorithmRSASHA256 uint8 = 8
    AlgorithmECDSAP256 uint8 = 13
    AlgorithmED25519   uint8 = 15
)
```

### Phase 2: Modify SignRRSet for Multi-Algorithm

Changed function signature from accepting `*ecdsa.PrivateKey` to `any`, and added `algorithm uint8` parameter:

```go
func SignRRSet(records []DNSRecord, privKey any, algorithm uint8, signerName string,
    keyTag uint16, inception, expiration uint32) (DNSRecord, error)
```

The function switches on algorithm type:
- **Algorithm 13**: Uses `ecdsa.Sign` with P-256, produces 64-byte R||S signature
- **Algorithm 8**: Uses `rsa.SignPKCS1v15` with SHA-256
- **Algorithm 15**: Uses `ed25519.Sign` with 32-byte seed

### Phase 3: Modify VerifyRRSet for Multi-Algorithm

Added separate key extraction functions per RFC specifications:
- `extractRSAPublicKey` - RSA public key stored as big-endian integer, E=65537
- `extractED25519PublicKey` - 32-byte Ed25519 public key
- `extractECDSAPublicKey` - Extended to handle both RFC 6605 (64-byte X||Y) and SEC1 uncompressed (65-byte 0x04||X||Y) formats

Verification switch in `VerifyRRSet` routes to the appropriate verification function based on the RRSIG algorithm.

### Phase 4: Update Call Sites

Systematically updated all callers of `SignRRSet` across:
- `internal/dns/packet/dnssec_test.go`
- `internal/dns/packet/dnssec_extra_test.go`
- `internal/dns/packet/dnssec_logic_test.go`
- `internal/dns/server/dnssec_integration_test.go`
- `internal/core/services/dnssec_service.go`

### Phase 5: Tests

Added comprehensive round-trip tests:
- `TestSignAndVerify_RSASHA256` - Full RSA 2048-bit sign/verify
- `TestSignAndVerify_ED25519` - Full Ed25519 sign/verify
- `TestVerifyRRSet_UnsupportedAlgorithm` - Ensures unknown algorithms return `ErrUnsupportedAlgorithm`

## Key Implementation Details

### RSA Key Storage

RSA public keys in DNSKEY RDATA are stored as a raw big-endian integer (the modulus N). The exponent is hardcoded to 65537 per DNSSEC conventions (RFC 5702).

```go
n := new(big.Int).SetBytes(dnskey.PublicKey)
e := 65537
return &rsa.PublicKey{N: n, E: e}
```

### Ed25519 Key Handling

`SignRRSet` receives Ed25519 private key as `[ed25519.PrivateKeySize]byte` (32-byte seed) to match the underlying `ed25519.Sign` API:

```go
ed25519Priv, ok := privKey.([ed25519.PrivateKeySize]byte)
if !ok {
    return DNSRecord{}, ErrInvalidSignature
}
sigData = ed25519.Sign(ed25519Priv[:], buf.Buf[:buf.Position()])
```

### DNSKEY Protocol Field

All DNSKEY records use protocol 3 (required by RFC 4034). This is enforced in `ComputeKeyTag` and `SignRRSet`.

## Consequences

### Positive
- Full compatibility with production DNS infrastructure using RSA or Ed25519
- All three RFC 8624 algorithms now supported for both signing and validation
- Minimal code duplication through shared canonical wire format functions
- Algorithm-specific code paths keep the core verification logic clean

### Negative
- Larger `SignRRSet` function with three code paths instead of one
- Test coverage must verify all three algorithms independently

### Trade-offs
- Chose `any` for private key type rather than `crypto.Signer` interface to avoid interface conversion complexity in tests
- Hardcoded RSA exponent E=65537 is standard in DNSSEC but assumes compliant keys