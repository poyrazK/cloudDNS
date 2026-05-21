# DNSSEC (DNS Security Extensions)

DNSSEC adds cryptographic authentication to DNS responses, allowing resolvers to verify that responses genuinely originate from the authoritative DNS server and were not tampered with in transit.

## Overview

cloudDNS implements full DNSSEC support:

- **Zone Signing**: Automatically sign zone data with DNSKEY/KEY records
- **Response Validation**: Verify signatures on incoming responses before returning to clients
- **Trust Anchors**: Manual configuration of trusted DNSKEYs
- **AD Bit**: Set the Authenticated Data bit on validated responses
- **EDE Codes**: RFC 8914 Extended DNS Error codes for debugging failures

## How DNSSEC Works

### The Problem

DNS was designed for reliability, not security. An attacker can:
- Intercept DNS queries and return false answers
- Poison DNS caches with fraudulent records
- Perform man-in-the-middle attacks on DNS traffic

### The Solution

DNSSEC adds cryptographic signatures to DNS data:

```
Traditional DNS:
  Client ──────▶ Resolver ──────▶ Nameserver
                ◀─────── Response (unsigned)

DNSSEC:
  Client ──────▶ Resolver ──────▶ Nameserver
                ◀─────── Signed Response (RRSIG + DNSKEY)
                         │
                         ▼
                   Signature verified!
```

### Key Concepts

#### DNSKEY Records

The DNSSEC signing keys. There are two types:

| Type | Flag | Purpose |
|------|------|---------|
| **KSK** (Key Signing Key) | 257 | Signs the ZSK and is published in DS records at the parent |
| **ZSK** (Zone Signing Key) | 256 | Signs all other records in the zone |

#### RRSIG (Resource Record Signature)

Cryptographic signatures for record sets. Each RRset (group of records with same name/type) has an RRSIG covering it.

#### DS (Delegation Signer) Records

Published by parent zones. Contains a hash of the child's KSK, establishing the trust chain from root to leaf zones.

#### NSEC/NSEC3

Records that prove a name or record type does not exist (authenticated denial of existence).

## DNSSEC Modes

cloudDNS supports three validation modes:

| Mode | Description |
|------|-------------|
| `disabled` | No DNSSEC validation performed |
| `ad-bit-only` | Set AD bit on validated responses; return unsigned responses normally |
| `strict` | Return SERVFAIL + EDE for invalid signatures |

### Configuration Example

```yaml
dnssec:
  enabled: true
  mode: strict
  trust_anchors:
    ".": "BSDiA8IA6XZ8xF8H5zPQIgF4S..."  # Root DNSKEY (base64)
    "com.": "K8F+8gAIx5LZ5qJ1vL..."        # .com DNSKEY (base64)
```

## EDE (Extended DNS Errors)

When DNSSEC validation fails, cloudDNS returns RFC 8914 Extended DNS Error codes to help diagnose the issue:

| Code | Name | Meaning |
|------|------|---------|
| 0 | Other | Unclassified error |
| 1 | UnsupportedDNSKEYAlgo | Algorithm not supported |
| 4 | Bogus | Signature verification failed |
| 6 | SignatureExpired | Signature has expired |
| 7 | SignatureNotYetValid | Signature not yet valid |
| 9 | DNSKEYMissing | Matching DNSKEY not found |
| 17 | TrustAnchorUnknown | Trust anchor not configured |

### Example: dig Output with EDE

```
;; EDNS: version: 0, flags:; udp: 4096
;; EDE: 6 : signature-expired
```

## Supported Algorithms

cloudDNS DNSSEC implementation supports five algorithms per RFC 8624:

| Algorithm | Name | Signing | Verification |
|-----------|------|---------|--------------|
| 8 | RSASHA256 | ✅ Full | ✅ Full |
| 13 | ECDSAP256SHA256 | ✅ Full | ✅ Full |
| 14 | ECDSAP384SHA384 | ✅ Full | ✅ Full |
| 15 | ED25519 | ✅ Full | ✅ Full |
| 16 | ED448 | ✅ Full | ✅ Full |

All five algorithms support both zone signing (via `SignRRSet`) and response validation (via `VerifyRRSet`).

### Algorithm Details

**RSA SHA-256 (Algorithm 8)**
- Key size: 2048-bit recommended (128-512 byte modulus supported)
- Uses PKCS#1 v1.5 signature scheme per RFC 5702
- Most widely supported algorithm in DNS resolvers

**ECDSA P-256 SHA-256 (Algorithm 13)**
- 64-byte public key in RFC 6605 X||Y format
- Fast verification, small signature size (64 bytes)
- Default algorithm for new zones

**ECDSA P-384 SHA-384 (Algorithm 14)**
- 96-byte public key in RFC 6605 X||Y format
- Higher security margin than P-256 (384-bit vs 256-bit curve)
- Uses SHA-384 for hashing
- Recommended for KSK operations where maximum security is required

**Ed25519 (Algorithm 15)**
- 32-byte public key per RFC 8080
- Fast signing and verification
- Small signature and key sizes

**Ed448 (Algorithm 16)**
- 57-byte public key per RFC 8080
- Higher security margin than Ed25519 (448-bit vs 255-bit curve)
- Uses SHA-512 for hashing (Ed25519 uses SHA-512 as well, but with different parameters)

## Limitations (v1.0 MVP)

- **NSEC only**: No NSEC3 support (NSEC is used for authenticated denial)
- **Manual trust anchors**: No automatic trust anchor bootstrap from root
- **No chain validation**: Validates against trust anchor but doesn't verify full chain to root

## DNSSEC in the Resolution Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Query                             │
│                   (with DO flag = 1)                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Resolution Engine                           │
│              (recursive resolution + DNSSEC)                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
    ┌─────────────────┐     ┌─────────────────┐
    │  Fetch DNSKEYs  │     │  Fetch Zone     │
    │  if DO=1        │     │  Records        │
    └────────┬────────┘     └────────┬────────┘
             │                       │
             └───────────┬───────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Validate RRSets   │
              │  (signature check) │
              └────────┬────────────┘
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
         Valid            Invalid
              │                 │
              │         ┌───────┴───────┐
              │         │               │
              │         ▼               ▼
              │      Mode=strict    Mode=ad-bit-only
              │      SERVFAIL+EDE   Return (AD=0)
              │                 │
              └────────┬─────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Set AD bit=1   │
              │ Return Response │
              └─────────────────┘
```

## Query Examples

### Check if a zone is signed

```bash
dig DNSKEY cloudflare.com +short
```

### Validate a response

```bash
dig A www.cloudflare.com +dnssec +ad @1.1.1.1
```

### Check EDE on failure

```bash
dig A signed-zone.example.com +dnssec +bufsize=2048
```

## References

- [RFC 4033](https://tools.ietf.org/rfc/rfc4033) - DNSSEC Protocol
- [RFC 4034](https://tools.ietf.org/rfc/rfc4034) - Resource Records
- [RFC 4035](https://tools.ietf.org/rfc/rfc4035) - Protocol Modifications
- [RFC 6605](https://tools.ietf.org/rfc/rfc6605) - ECDSA for DNSSEC
- [RFC 8914](https://tools.ietf.org/rfc/rfc8914) - Extended DNS Errors

## Architecture Decision

See [ADR 0008](./decisions/0008-dnssec-validation.md) for detailed architecture documentation.

## Implementation Roadmap

See [roadmap-dnssec-validation.md](./roadmap-dnssec-validation.md) for the implementation timeline.
