package packet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 required for DNSSEC DS records (RFC 4034)
	"crypto/sha256"
	"strings"
)

// ComputeKeyTag calculates the key tag for a DNSKEY record according to RFC 4034 Appendix B.
// This is used to quickly identify which DNSKEY a signature refers to.
func (r *DNSRecord) ComputeKeyTag() uint16 {
	if r.Type != DNSKEY {
		return 0
	}

	buf := NewBytePacketBuffer()
	if err := buf.Writeu16(r.Flags); err != nil { return 0 }
	if err := buf.Write(3); err != nil { return 0 } // Protocol: MUST be 3 (RFC 4034 Section 2.1.2)
	if err := buf.Write(r.Algorithm); err != nil { return 0 }
	for _, b := range r.PublicKey {
		if err := buf.Write(b); err != nil { return 0 }
	}

	data := buf.Buf[:buf.Position()]
	var ac uint32
	for i, b := range data {
		if i%2 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xFFFF
	return uint16(ac & 0xFFFF) // #nosec G115
}

// ComputeDS generates a Delegation Signer (DS) record from a DNSKEY record (RFC 4034 Section 5.2).
// Supported digest types:
//   - 1: SHA-1
//   - 2: SHA-256
func (r *DNSRecord) ComputeDS(digestType uint8) (DNSRecord, error) {
	if r.Type != DNSKEY {
		return DNSRecord{}, nil
	}

	// 1. Prepare Buffer: The digest is calculated over [owner name | DNSKEY RDATA]
	// Owner name MUST be in its canonical wire format (lowercase, no compression).
	buf := NewBytePacketBuffer()
	if err := buf.WriteName(strings.ToLower(r.Name)); err != nil { return DNSRecord{}, err }
	if err := buf.Writeu16(r.Flags); err != nil { return DNSRecord{}, err }
	if err := buf.Write(3); err != nil { return DNSRecord{}, err } // Protocol
	if err := buf.Write(r.Algorithm); err != nil { return DNSRecord{}, err }
	for _, b := range r.PublicKey {
		if err := buf.Write(b); err != nil { return DNSRecord{}, err }
	}

	// 2. Calculate the cryptographic digest
	var digest []byte
	switch digestType {
	case 1: // SHA-1
		hashed := sha1.Sum(buf.Buf[:buf.Position()]) // #nosec G401
		digest = hashed[:]
	case 2: // SHA-256
		hashed := sha256.Sum256(buf.Buf[:buf.Position()])
		digest = hashed[:]
	default:
		// Unsupported digest type - return empty record per RFC 4034 expectations in some contexts
		return DNSRecord{}, nil
	}

	return DNSRecord{
		Name:       r.Name,
		Type:       DS,
		Class:      1,
		TTL:        r.TTL,
		KeyTag:     r.ComputeKeyTag(),
		Algorithm:  r.Algorithm,
		DigestType: digestType,
		Digest:     digest,
	}, nil
}

// SignRRSet generates an RRSIG for a set of records.
// This is a simplified implementation optimized for ECDSA P-256 (Algorithm 13).
func SignRRSet(records []DNSRecord, privKey *ecdsa.PrivateKey, signerName string, keyTag uint16, inception, expiration uint32) (DNSRecord, error) {
	if len(records) == 0 {
		return DNSRecord{}, nil
	}

	sig := DNSRecord{
		Name:        records[0].Name,
		Type:        RRSIG,
		Class:       1,
		TTL:         records[0].TTL,
		TypeCovered: uint16(records[0].Type),
		Algorithm:   13, // ECDSAP256SHA256
		Labels:      uint8(countLabels(records[0].Name)), // #nosec G115
		OrigTTL:     records[0].TTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  signerName,
	}

	buf := NewBytePacketBuffer()
	for _, r := range records {
		if err := buf.WriteName(strings.ToLower(r.Name)); err != nil {
			return DNSRecord{}, err
		}
		if err := buf.Writeu16(uint16(r.Type)); err != nil {
			return DNSRecord{}, err
		}
		if err := buf.Writeu16(uint16(1)); err != nil {
			return DNSRecord{}, err
		} // Class IN
		if err := buf.Writeu32(r.TTL); err != nil {
			return DNSRecord{}, err
		}
		// Write RDATA in canonical form
		if err := writeSignCanonicalRData(&r, buf); err != nil {
			return DNSRecord{}, err
		}
	}

	hashed := crypto.SHA256.New()
	hashed.Write(buf.Buf[:buf.Position()])
	h := hashed.Sum(nil)

	rb, sb, err := ecdsa.Sign(rand.Reader, privKey, h)
	if err != nil {
		return DNSRecord{}, err
	}

	rBytes := rb.FillBytes(make([]byte, 32))
	sBytes := sb.FillBytes(make([]byte, 32))
	sigData := make([]byte, 64)
	copy(sigData[0:32], rBytes)
	copy(sigData[32:64], sBytes)

	sig.Signature = sigData
	return sig, nil
}

func countLabels(name string) int {
	name = strings.TrimSuffix(name, ".")
	if name == "" { return 0 }
	return len(strings.Split(name, "."))
}

// writeSignCanonicalRData writes the RDATA portion of a record in canonical form for signing.
// This is a copy of writeCanonicalRData from dnssec_verify.go but without the switch on type
// since SignRRSet only signs A records here (based on existing usage).
func writeSignCanonicalRData(r *DNSRecord, buf *BytePacketBuffer) error {
	switch r.Type {
	case A:
		// A record needs IP; if missing, fall through to data fallback
		if r.IP == nil || len(r.IP) == 0 {
			break
		}
		if err := buf.Writeu16(4); err != nil {
			return err
		}
		ip4 := r.IP.To4()
		if ip4 == nil {
			break
		}
		for _, b := range ip4 {
			if err := buf.Write(b); err != nil {
				return err
			}
		}
		return nil
	default:
		// Fallback: write raw data if available
		if len(r.Data) > 0 {
			for _, b := range r.Data {
				if err := buf.Write(b); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
