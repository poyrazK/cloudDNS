package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
)

var (
	// ErrSignatureExpired indicates the signature expiration time has passed.
	ErrSignatureExpired = errors.New("dnssec: signature is expired")
	// ErrSignatureNotYetValid indicates the signature inception time has not been reached.
	ErrSignatureNotYetValid = errors.New("dnssec: signature is not yet valid")
	// ErrKeyTagMismatch indicates the RRSIG key tag doesn't match the DNSKEY.
	ErrKeyTagMismatch = errors.New("dnssec: key tag mismatch")
	// ErrAlgorithmMismatch indicates the RRSIG algorithm doesn't match the DNSKEY.
	ErrAlgorithmMismatch = errors.New("dnssec: algorithm mismatch")
	// ErrInvalidDNSKEY indicates the DNSKEY has invalid flags.
	ErrInvalidDNSKEY = errors.New("dnssec: invalid DNSKEY flags")
	// ErrInvalidSignature indicates the signature verification failed.
	ErrInvalidSignature = errors.New("dnssec: invalid signature")
	// ErrNoPublicKey indicates the DNSKEY has no public key data.
	ErrNoPublicKey = errors.New("dnssec: no public key in DNSKEY")
	// ErrUnsupportedAlgorithm indicates the algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")
)

// writeBytes writes a byte slice to the buffer using individual byte writes.
func writeBytes(buf *BytePacketBuffer, data []byte) error {
	for _, b := range data {
		if err := buf.Write(b); err != nil {
			return err
		}
	}
	return nil
}

// CanonicalWireMarshal serializes a DNS record in canonical wire format per RFC 4034 Section 6.
// This format is used for DNSSEC signature verification.
func CanonicalWireMarshal(r *DNSRecord, buf *BytePacketBuffer) error {
	// Owner name: lowercase, no compression
	if err := buf.WriteName(strings.ToLower(r.Name)); err != nil {
		return err
	}

	switch r.Type {
	case DNSKEY:
		// Canonical DNSKEY RDATA: flags | protocol | algorithm | publickey
		if err := buf.Writeu16(r.Flags); err != nil {
			return err
		}
		if err := buf.Write(3); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		if err := writeBytes(buf, r.PublicKey); err != nil {
			return err
		}
	case RRSIG:
		// Canonical RRSIG RDATA: typecovered | algorithm | labels | origttl |
		// expiration | inception | keytag | signername | signature
		if err := buf.Writeu16(r.TypeCovered); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		if err := buf.Write(r.Labels); err != nil {
			return err
		}
		if err := buf.Writeu32(r.OrigTTL); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Expiration); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Inception); err != nil {
			return err
		}
		if err := buf.Writeu16(r.KeyTag); err != nil {
			return err
		}
		if err := buf.WriteName(strings.ToLower(r.SignerName)); err != nil {
			return err
		}
		if err := writeBytes(buf, r.Signature); err != nil {
			return err
		}
	case DS:
		// Canonical DS RDATA: keytag | algorithm | digesttype | digest
		if err := buf.Writeu16(r.KeyTag); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		if err := buf.Write(r.DigestType); err != nil {
			return err
		}
		if err := writeBytes(buf, r.Digest); err != nil {
			return err
		}
	case A:
		if err := buf.Writeu16(4); err != nil {
			return err
		}
		ip4 := r.IP.To4()
		if ip4 == nil {
			return errors.New("invalid IPv4 address")
		}
		return writeBytes(buf, ip4)
	case AAAA:
		if err := buf.Writeu16(16); err != nil {
			return err
		}
		return writeBytes(buf, r.IP.To16())
	case CNAME, NS, PTR, MD, MF, MB, MG, MR:
		return buf.WriteName(strings.ToLower(r.Host))
	case TXT:
		// TXT: length prefix followed by ASCII bytes
		for _, chunk := range stringsToChunks(r.Txt) {
			if err := buf.Write(byte(len(chunk))); err != nil {
				return err
			}
			if err := writeBytes(buf, []byte(chunk)); err != nil {
				return err
			}
		}
		return nil
	case MX:
		if err := buf.Writeu16(r.Priority); err != nil {
			return err
		}
		return buf.WriteName(strings.ToLower(r.Host))
	case SOA:
		if err := buf.WriteName(strings.ToLower(r.MName)); err != nil {
			return err
		}
		if err := buf.WriteName(strings.ToLower(r.RName)); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Serial); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Refresh); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Retry); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Expire); err != nil {
			return err
		}
		return buf.Writeu32(r.Minimum)
	case SRV:
		if err := buf.Writeu16(r.Priority); err != nil {
			return err
		}
		if err := buf.Writeu16(r.Weight); err != nil {
			return err
		}
		if err := buf.Writeu16(r.Port); err != nil {
			return err
		}
		return buf.WriteName(strings.ToLower(r.Host))
	case NSEC:
		if err := buf.WriteName(strings.ToLower(r.NextName)); err != nil {
			return err
		}
		return writeBytes(buf, r.TypeBitMap)
	default:
		// Fallback: write raw data if available
		if len(r.Data) > 0 {
			return writeBytes(buf, r.Data)
		}
	}
	return nil
}

// stringsToChunks splits a string into 255-byte chunks for TXT records.
func stringsToChunks(s string) []string {
	var chunks []string
	for i := 0; i < len(s); i += 255 {
		end := i + 255
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// VerifyRRSet verifies an RRSIG signature over an RRSet.
// It supports ECDSA P-256 (Algorithm 13) signatures.
func VerifyRRSet(rrset []DNSRecord, rrsig DNSRecord, dnskey DNSRecord, now uint32) (bool, error) {
	if len(rrset) == 0 {
		return false, errors.New("dnssec: empty rrset")
	}

	// 1. Check signature expiration
	if now > rrsig.Expiration {
		return false, ErrSignatureExpired
	}

	// 2. Check signature inception
	if now < rrsig.Inception {
		return false, ErrSignatureNotYetValid
	}

	// 3. Verify key tag matches
	if rrsig.KeyTag != dnskey.ComputeKeyTag() {
		return false, ErrKeyTagMismatch
	}

	// 4. Verify algorithm matches
	if rrsig.Algorithm != dnskey.Algorithm {
		return false, ErrAlgorithmMismatch
	}

	// 5. Check DNSKEY type
	if dnskey.Type != DNSKEY {
		return false, ErrInvalidDNSKEY
	}

	// 6. Extract ECDSA public key from DNSKEY
	publicKey, err := extractECDSAPublicKey(dnskey)
	if err != nil {
		return false, err
	}

	// 7. Reconstruct canonical wire format of RRSIG/RRset per RFC 4034 Section 8.1
	buf := NewBytePacketBuffer()

	// Prepend RRSIG RDATA fields (excluding Signature)
	if err := buf.Writeu16(rrsig.TypeCovered); err != nil {
		return false, err
	}
	if err := buf.Write(rrsig.Algorithm); err != nil {
		return false, err
	}
	if err := buf.Write(rrsig.Labels); err != nil {
		return false, err
	}
	if err := buf.Writeu32(rrsig.OrigTTL); err != nil {
		return false, err
	}
	if err := buf.Writeu32(rrsig.Expiration); err != nil {
		return false, err
	}
	if err := buf.Writeu32(rrsig.Inception); err != nil {
		return false, err
	}
	if err := buf.Writeu16(rrsig.KeyTag); err != nil {
		return false, err
	}
	if err := buf.WriteName(strings.ToLower(rrsig.SignerName)); err != nil {
		return false, err
	}

	// Write canonical RRset per RFC 4034: owner|type|class|Original TTL|RDLENGTH|RDATA
	for _, r := range rrset {
		// Write owner name in canonical form
		if err := buf.WriteName(strings.ToLower(r.Name)); err != nil {
			return false, err
		}
		if err := buf.Writeu16(uint16(r.Type)); err != nil {
			return false, err
		}
		if err := buf.Writeu16(1); err != nil { // Class IN
			return false, err
		}
		if err := buf.Writeu32(rrsig.OrigTTL); err != nil {
			return false, err
		}
		// Write RDATA in canonical form
		if err := writeCanonicalRData(&r, buf); err != nil {
			return false, err
		}
	}

	// 8. Compute hash
	hashed := sha256.Sum256(buf.Buf[:buf.Position()])

	// 9. Extract R and S from signature
	if len(rrsig.Signature) < 64 {
		return false, ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(rrsig.Signature[0:32])
	s := new(big.Int).SetBytes(rrsig.Signature[32:64])

	// 10. Verify ECDSA signature
	if !ecdsa.Verify(publicKey, hashed[:], r, s) {
		return false, ErrInvalidSignature
	}

	return true, nil
}

// extractECDSAPublicKey extracts an ECDSA P-256 public key from a DNSKEY record.
// It supports both RFC 6605 format (64-byte X||Y for Algorithm 13) and
// SEC1 uncompressed format (65-byte 0x04||X||Y).
func extractECDSAPublicKey(dnskey DNSRecord) (*ecdsa.PublicKey, error) {
	var x, y *big.Int

	switch {
	case dnskey.Algorithm == 13 && len(dnskey.PublicKey) == 64:
		// RFC 6605: ECDSAP256SHA256 uses X||Y format (64 bytes)
		x = new(big.Int).SetBytes(dnskey.PublicKey[0:32])
		y = new(big.Int).SetBytes(dnskey.PublicKey[32:64])
	case len(dnskey.PublicKey) >= 65 && dnskey.PublicKey[0] == 0x04:
		// SEC1 uncompressed format: 0x04 || X (32 bytes) || Y (32 bytes)
		x = new(big.Int).SetBytes(dnskey.PublicKey[1:33])
		y = new(big.Int).SetBytes(dnskey.PublicKey[33:65])
	default:
		if len(dnskey.PublicKey) < 64 {
			return nil, ErrNoPublicKey
		}
		return nil, ErrUnsupportedAlgorithm
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// writeCanonicalRData writes the RDATA portion of a record in canonical form.
func writeCanonicalRData(r *DNSRecord, buf *BytePacketBuffer) error {
	switch r.Type {
	case A:
		if err := buf.Writeu16(4); err != nil {
			return err
		}
		ip4 := r.IP.To4()
		if ip4 == nil {
			return errors.New("invalid IPv4 address")
		}
		return writeBytes(buf, ip4)
	case AAAA:
		if err := buf.Writeu16(16); err != nil {
			return err
		}
		return writeBytes(buf, r.IP.To16())
	case CNAME, NS, PTR:
		return buf.WriteName(strings.ToLower(r.Host))
	case MX:
		if err := buf.Writeu16(r.Priority); err != nil {
			return err
		}
		return buf.WriteName(strings.ToLower(r.Host))
	case TXT:
		for _, chunk := range stringsToChunks(r.Txt) {
			if err := buf.Write(byte(len(chunk))); err != nil {
				return err
			}
			if err := writeBytes(buf, []byte(chunk)); err != nil {
				return err
			}
		}
		return nil
	case SOA:
		if err := buf.WriteName(strings.ToLower(r.MName)); err != nil {
			return err
		}
		if err := buf.WriteName(strings.ToLower(r.RName)); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Serial); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Refresh); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Retry); err != nil {
			return err
		}
		if err := buf.Writeu32(r.Expire); err != nil {
			return err
		}
		return buf.Writeu32(r.Minimum)
	case SRV:
		if err := buf.Writeu16(r.Priority); err != nil {
			return err
		}
		if err := buf.Writeu16(r.Weight); err != nil {
			return err
		}
		if err := buf.Writeu16(r.Port); err != nil {
			return err
		}
		return buf.WriteName(strings.ToLower(r.Host))
	case DNSKEY:
		if err := buf.Writeu16(r.Flags); err != nil {
			return err
		}
		if err := buf.Write(3); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		return writeBytes(buf, r.PublicKey)
	case DS:
		if err := buf.Writeu16(r.KeyTag); err != nil {
			return err
		}
		if err := buf.Write(r.Algorithm); err != nil {
			return err
		}
		if err := buf.Write(r.DigestType); err != nil {
			return err
		}
		return writeBytes(buf, r.Digest)
	case NSEC:
		if err := buf.WriteName(strings.ToLower(r.NextName)); err != nil {
			return err
		}
		return writeBytes(buf, r.TypeBitMap)
	default:
		if len(r.Data) > 0 {
			return writeBytes(buf, r.Data)
		}
		return nil
	}
}

// VerifyDNSKEYMatchesDS verifies that a DS record matches a DNSKEY record.
// It recomputes the DS digest and compares it with the provided DS record.
func VerifyDNSKEYMatchesDS(dnskey DNSRecord, ds DNSRecord) (bool, error) {
	// Compute what the DS should be
	computedDS, err := dnskey.ComputeDS(ds.DigestType)
	if err != nil {
		return false, err
	}

	// Compare key tags
	if computedDS.KeyTag != ds.KeyTag {
		return false, ErrKeyTagMismatch
	}

	// Compare algorithms (prevents tampered DS from passing)
	if computedDS.Algorithm != ds.Algorithm {
		return false, ErrAlgorithmMismatch
	}

	// Compare digests
	if string(computedDS.Digest) != string(ds.Digest) {
		return false, errors.New("dnssec: DS digest mismatch")
	}

	return true, nil
}

// ValidateDNSKEYFormat verifies that a DNSKEY has valid structure.
// It checks the key tag is non-zero and the public key is parseable.
// Note: This does NOT perform cryptographic self-signature verification.
// For full self-signature validation, use VerifyRRSet with the DNSKEY RRset and its RRSIG.
func ValidateDNSKEYFormat(dnskey DNSRecord) (bool, error) {
	if dnskey.Type != DNSKEY {
		return false, ErrInvalidDNSKEY
	}

	// Check that we can extract a valid public key
	_, err := extractECDSAPublicKey(dnskey)
	if err != nil {
		return false, err
	}

	// Compute and verify key tag is non-zero
	tag := dnskey.ComputeKeyTag()
	if tag == 0 {
		return false, ErrInvalidDNSKEY
	}

	return true, nil
}

// FindMatchingDNSKEY finds a DNSKEY that can verify an RRSIG.
// It matches by key tag and algorithm.
func FindMatchingDNSKEY(rrsig DNSRecord, dnskeys []DNSRecord) *DNSRecord {
	for i := range dnskeys {
		dnskey := &dnskeys[i]
		if dnskey.Type != DNSKEY {
			continue
		}
		if rrsig.KeyTag == dnskey.ComputeKeyTag() && rrsig.Algorithm == dnskey.Algorithm {
			return dnskey
		}
	}
	return nil
}
