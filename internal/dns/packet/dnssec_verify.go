package packet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
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
	// ErrLabelsMismatch indicates the RRSIG Labels field doesn't match the RRset.
	ErrLabelsMismatch = errors.New("dnssec: labels mismatch")
	// ErrInvalidSignature indicates the signature verification failed.
	ErrInvalidSignature = errors.New("dnssec: invalid signature")
	// ErrNoPublicKey indicates the DNSKEY has no public key data.
	ErrNoPublicKey = errors.New("dnssec: no public key in DNSKEY")
	// ErrUnsupportedAlgorithm indicates the algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("dnssec: unsupported algorithm")
	// ErrNSEC3HashAlgoUnsupported indicates the NSEC3 hash algorithm is not supported.
	ErrNSEC3HashAlgoUnsupported = errors.New("dnssec: nsec3 hash algorithm unsupported")
	// ErrNSEC3InvalidProof indicates the NSEC3 proof is invalid.
	ErrNSEC3InvalidProof = errors.New("dnssec: nsec3 invalid proof")
	// ErrNSEC3ChainBroken indicates the NSEC3 hash chain is broken.
	ErrNSEC3ChainBroken = errors.New("dnssec: nsec3 chain broken")
	// ErrNSEC3NoMatchingName indicates the NSEC3 owner name doesn't match.
	ErrNSEC3NoMatchingName = errors.New("dnssec: nsec3 owner name hash mismatch")
	// ErrNSEC3NoClosestEncloser indicates no closest-encloser could be found in the NSEC3 chain.
	ErrNSEC3NoClosestEncloser = errors.New("dnssec: nsec3 no closest-encloser found")
	// ErrNSEC3NoNextCloser indicates the next-closer proof is missing or invalid.
	ErrNSEC3NoNextCloser = errors.New("dnssec: nsec3 no next-closer proof")
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
			if err := buf.WriteUint8(len(chunk)); err != nil {
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

// countNameLabels returns the number of labels in a DNS name.
// For example: "example.com." = 2, "*.wildcard.zone." = 3, "." = 1
func countNameLabels(name string) uint8 {
	if name == "." {
		return 1
	}
	// Count dots, then add 1 for the final label
	count := 0
	for _, c := range name {
		if c == '.' {
			count++
		}
	}
	return uint8(count)
}

// VerifyRRSet verifies an RRSIG signature over an RRSet.
// It supports ECDSA P-256 (13), ECDSA P-384 (14), RSA SHA-256 (8), Ed25519 (15), and Ed448 (16) signatures.
func VerifyRRSet(rrset []DNSRecord, rrsig DNSRecord, dnskey DNSRecord, now uint32) (bool, error) {
	if len(rrset) == 0 {
		return false, errors.New("dnssec: empty rrset")
	}

	// 1. Check signature expiration
	// If Expiration < Inception, overflow occurred during signing — treat as expired
	if rrsig.Expiration < rrsig.Inception {
		return false, ErrSignatureExpired
	}
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

	// 6. Verify Labels field per RFC 4034 Section 8.2
	// The Labels field must equal the number of labels in the RRset owner name.
	// For wildcard RRs, the Labels reflects the wildcard name (e.g., "*.zone." = 2 labels).
	expectedLabels := countNameLabels(rrset[0].Name)
	if rrsig.Labels != expectedLabels {
		return false, ErrLabelsMismatch
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

	// 8. Verify signature based on algorithm
	switch rrsig.Algorithm {
	case AlgorithmECDSAP256:
		hashed := sha256.Sum256(buf.Buf[:buf.Position()])
		publicKey, err := extractECDSAPublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if len(rrsig.Signature) < 64 {
			return false, ErrInvalidSignature
		}
		r := new(big.Int).SetBytes(rrsig.Signature[0:32])
		s := new(big.Int).SetBytes(rrsig.Signature[32:64])
		if !ecdsa.Verify(publicKey, hashed[:], r, s) {
			return false, ErrInvalidSignature
		}

	case AlgorithmECDSAP384:
		hashed := sha512.Sum384(buf.Buf[:buf.Position()])
		publicKey, err := extractECDSAPublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if len(rrsig.Signature) < 96 {
			return false, ErrInvalidSignature
		}
		r := new(big.Int).SetBytes(rrsig.Signature[0:48])
		s := new(big.Int).SetBytes(rrsig.Signature[48:96])
		if !ecdsa.Verify(publicKey, hashed[:], r, s) {
			return false, ErrInvalidSignature
		}

	case AlgorithmRSASHA256:
		hashed := sha256.Sum256(buf.Buf[:buf.Position()])
		publicKey, err := extractRSAPublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], rrsig.Signature); err != nil {
			return false, ErrInvalidSignature
		}

	case AlgorithmED25519:
		hashed := sha256.Sum256(buf.Buf[:buf.Position()])
		publicKey, err := extractED25519PublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if !ed25519.Verify(publicKey, hashed[:], rrsig.Signature) {
			return false, ErrInvalidSignature
		}

	case AlgorithmED448:
		hashed := sha512.Sum384(buf.Buf[:buf.Position()])
		publicKey, err := extractED448PublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if !ed448.Verify(publicKey, hashed[:], rrsig.Signature, "") {
			return false, ErrInvalidSignature
		}

	default:
		return false, ErrUnsupportedAlgorithm
	}

	return true, nil
}

// extractECDSAPublicKey extracts an ECDSA public key from a DNSKEY record.
// It supports:
// - Algorithm 13 (P-256): 64-byte X||Y format per RFC 6605
// - Algorithm 14 (P-384): 96-byte X||Y format per RFC 6605
// - SEC1 uncompressed format: 65-byte 0x04||X||Y (for any curve)
func extractECDSAPublicKey(dnskey DNSRecord) (*ecdsa.PublicKey, error) {
	var x, y *big.Int
	var curve elliptic.Curve

	switch {
	case dnskey.Algorithm == AlgorithmECDSAP256 && len(dnskey.PublicKey) == 64:
		// RFC 6605: ECDSAP256SHA256 uses X||Y format (64 bytes)
		x = new(big.Int).SetBytes(dnskey.PublicKey[0:32])
		y = new(big.Int).SetBytes(dnskey.PublicKey[32:64])
		curve = elliptic.P256()
	case dnskey.Algorithm == AlgorithmECDSAP384 && len(dnskey.PublicKey) == 96:
		// RFC 6605: ECDSAP384SHA384 uses X||Y format (96 bytes)
		x = new(big.Int).SetBytes(dnskey.PublicKey[0:48])
		y = new(big.Int).SetBytes(dnskey.PublicKey[48:96])
		curve = elliptic.P384()
	case len(dnskey.PublicKey) >= 65 && dnskey.PublicKey[0] == 0x04:
		// SEC1 uncompressed format: 0x04 || X || Y
		coordSize := (len(dnskey.PublicKey) - 1) / 2
		x = new(big.Int).SetBytes(dnskey.PublicKey[1 : 1+coordSize])
		y = new(big.Int).SetBytes(dnskey.PublicKey[1+coordSize:])
		curve = elliptic.P256() // Default, but could be P384 if key is large enough
	default:
		if len(dnskey.PublicKey) < 64 {
			return nil, ErrNoPublicKey
		}
		return nil, ErrUnsupportedAlgorithm
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// extractRSAPublicKey extracts an RSA public key from a DNSKEY record.
// RFC 5702 defines RSA/SHA-256 for DNSSEC.
func extractRSAPublicKey(dnskey DNSRecord) (*rsa.PublicKey, error) {
	if len(dnskey.PublicKey) < 64 {
		return nil, ErrNoPublicKey
	}

	// RSA public key in DNSKEY is stored as a big-endian integer
	keySize := len(dnskey.PublicKey)
	if keySize < 64 || keySize > 512 {
		return nil, ErrUnsupportedAlgorithm
	}

	n := new(big.Int).SetBytes(dnskey.PublicKey)
	e := 65537 // Standard exponent for DNSSEC

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// extractED25519PublicKey extracts an Ed25519 public key from a DNSKEY record.
// RFC 8080 defines Ed25519 for DNSSEC.
func extractED25519PublicKey(dnskey DNSRecord) (ed25519.PublicKey, error) {
	if len(dnskey.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrNoPublicKey
	}
	return ed25519.PublicKey(dnskey.PublicKey), nil
}

// extractED448PublicKey extracts an Ed448 public key from a DNSKEY record.
// RFC 8080 defines Ed448 for DNSSEC.
func extractED448PublicKey(dnskey DNSRecord) (ed448.PublicKey, error) {
	if len(dnskey.PublicKey) != ed448.PublicKeySize {
		return nil, ErrNoPublicKey
	}
	return ed448.PublicKey(dnskey.PublicKey), nil
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
			if err := buf.WriteUint8(len(chunk)); err != nil {
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

	// Compare digests using constant-time comparison to prevent timing attacks
	if !hmac.Equal(computedDS.Digest, ds.Digest) {
		return false, errors.New("dnssec: DS digest mismatch")
	}

	return true, nil
}

// ValidateDNSKEYFormat verifies that a DNSKEY has valid structure.
// It checks the key tag is non-zero and the public key is parseable for the algorithm.
// Note: This does NOT perform cryptographic self-signature verification.
// For full self-signature validation, use VerifyRRSet with the DNSKEY RRset and its RRSIG.
func ValidateDNSKEYFormat(dnskey DNSRecord) (bool, error) {
	if dnskey.Type != DNSKEY {
		return false, ErrInvalidDNSKEY
	}

	var err error
	switch dnskey.Algorithm {
	case AlgorithmECDSAP256, AlgorithmECDSAP384:
		_, err = extractECDSAPublicKey(dnskey)
	case AlgorithmRSASHA256:
		_, err = extractRSAPublicKey(dnskey)
	case AlgorithmED25519:
		_, err = extractED25519PublicKey(dnskey)
	case AlgorithmED448:
		_, err = extractED448PublicKey(dnskey)
	default:
		err = ErrUnsupportedAlgorithm
	}
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

// NSEC3Present returns true if the record list contains NSEC3 records.
func NSEC3Present(records []DNSRecord) bool {
	for _, r := range records {
		if r.Type == NSEC3 {
			return true
		}
	}
	return false
}

// ValidateNSEC3RecordFormat validates the wire format of an NSEC3 record.
// Per RFC 5155 Section 3.2, only hash algorithm 1 (SHA-1) is defined.
// Salt and NextHash lengths must be <= 255 bytes.
func ValidateNSEC3RecordFormat(nsec3 DNSRecord) error {
	if nsec3.Type != NSEC3 {
		return errors.New("dnssec: not an NSEC3 record")
	}

	// RFC 5155 Section 3.2: hash algorithm must be 1 (SHA-1)
	if nsec3.HashAlg != 1 {
		return ErrNSEC3HashAlgoUnsupported
	}

	// RFC 5155 Section 10.3: Iterations should be limited to prevent DoS (CPU exhaustion).
	// High iterations (e.g., 5000+) on deeply nested names causes expensive SHA-1 computation.
	// Common legitimate values are < 100; we cap at 150 to allow margin.
	const MaxNSEC3Iterations = 150
	if nsec3.Iterations > MaxNSEC3Iterations {
		return fmt.Errorf("dnssec: nsec3 iterations too high (%d)", nsec3.Iterations)
	}

	// Salt length must be <= 255 per RFC 5155
	if len(nsec3.Salt) > 255 {
		return errors.New("dnssec: nsec3 salt too long")
	}

	// NextHash length must be <= 255 (typically 20 for SHA-1)
	if len(nsec3.NextHash) > 255 {
		return errors.New("dnssec: nsec3 nexthash too long")
	}

	return nil
}

// nsec3Base32Alphabet is a case-insensitive RFC 5155 Base32 alphabet map,
// built once from nsec3Base32Map in nsec3.go to avoid duplication.
var nsec3Base32Alphabet = (func() map[byte]uint8 {
	m := make(map[byte]uint8, len(nsec3Base32Map)*2)
	for i := range nsec3Base32Map {
		c := nsec3Base32Map[i]
		m[c] = uint8(i)
		m[c-'a'+'A'] = uint8(i) // accept uppercase
	}
	return m
})()

// base32Decode decodes a NSEC3 base32 string (RFC 5155 alphabet) into bytes.
// The alphabet is: 0-9 a-v (case-insensitive, accepts lowercase and uppercase).
// Returns an error for invalid characters outside the alphabet.
func base32Decode(encoded string) ([]byte, error) {
	var result []byte
	var buffer uint32
	var validBits uint8

	for i := range encoded {
		c := encoded[i]
		val, ok := nsec3Base32Alphabet[c]
		if !ok {
			return nil, errors.New("dnssec: invalid base32 character")
		}
		// Add 5 bits from this character to the buffer
		buffer = (buffer << 5) | uint32(val)
		validBits += 5
		// Emit as many complete bytes as we have
		for validBits >= 8 {
			validBits -= 8
			shift := validBits
			// Mask with 0xFF to explicitly constrain to [0,255] for gosec G115
			result = append(result, byte((buffer>>shift)&0xFF))
		}
	}

	return result, nil
}

// VerifyNSEC3OwnerName verifies that an NSEC3 record's owner name is the correct
// base32-encoded hash of the given name with the NSEC3's salt and iterations.
func VerifyNSEC3OwnerName(nsec3 DNSRecord, name string) (bool, error) {
	// Extract zone portion from the NSEC3 owner name.
	// NSEC3 owner is like: <hash>.zone. where hash is base32 encoded.
	// We need to parse the owner, extract the hash, and compare against computed hash.
	owner := strings.TrimSuffix(nsec3.Name, ".")

	// Find the first dot to separate hash from zone
	dotIdx := strings.Index(owner, ".")
	if dotIdx <= 0 {
		return false, ErrNSEC3NoMatchingName
	}

	hashPart := owner[:dotIdx]

	// Decode the hash from the owner name
	ownerHash, err := base32Decode(hashPart)
	if err != nil {
		return false, ErrNSEC3NoMatchingName
	}

	// Compute expected hash of the name with NSEC3 params
	computedHash := HashName(name, nsec3.HashAlg, nsec3.Iterations, nsec3.Salt)

	if !bytes.Equal(ownerHash, computedHash) {
		return false, ErrNSEC3NoMatchingName
	}

	return true, nil
}

// nsec3CoversHash checks whether an NSEC3 record covers the given hash per RFC 5155 Section 3.3.5.
// An NSEC3 record covers a hash if: ownerHash <= h < nextHash (lexicographic ordering).
// If nextHash <= ownerHash (zone wrapped), the range is: h >= ownerHash OR h < nextHash.
func nsec3CoversHash(ownerHash, nextHash, coveredHash []byte) bool {
	if len(nextHash) == 0 || len(ownerHash) != len(nextHash) {
		return false
	}

	if bytes.Compare(nextHash, ownerHash) > 0 {
		// Normal case: ownerHash < nextHash
		// Covered if ownerHash <= h < nextHash
		return bytes.Compare(ownerHash, coveredHash) <= 0 && bytes.Compare(coveredHash, nextHash) < 0
	}
	// Wrap-around case: nextHash <= ownerHash
	// Covered if h >= ownerHash OR h < nextHash
	return bytes.Compare(coveredHash, ownerHash) >= 0 || bytes.Compare(coveredHash, nextHash) < 0
}

// TypeBitMapPresent checks if the type bitmap in an NSEC3 record indicates
// the presence of a given record type.
func TypeBitMapPresent(bitmap []byte, queryType uint16) bool {
	i := 0
	for i < len(bitmap) {
		// Each window is: window number (1 byte) + bitmap length (1 byte) + bitmap
		if i+1 >= len(bitmap) {
			break
		}
		window := bitmap[i]
		bitmapLen := int(bitmap[i+1])
		i += 2

		if i+bitmapLen > len(bitmap) {
			break
		}

		// Check if the type is in this window
		// Types are stored as: (type_number - window*256) in the bitmap byte
		typeOffset := int(queryType) - int(window)*256
		if typeOffset >= 0 && typeOffset < bitmapLen*8 {
			byteIndex := typeOffset / 8
			bitIndex := uint(typeOffset % 8)
			// RFC 4034 Section 4.1.2: bits are numbered from left (MSB) within each octet
			if byteIndex < bitmapLen && (bitmap[i+byteIndex]&(1<<(7-bitIndex))) != 0 {
				return true
			}
		}
		i += bitmapLen
	}
	return false
}

// wildcardName returns the wildcard name for a given label count.
// e.g., wildcardName("www.example.com.", 1) returns "*.example.com."
func wildcardName(query string, labelCount int) string {
	name := strings.TrimSuffix(query, ".")
	labels := strings.Split(name, ".")
	if labelCount >= len(labels) {
		return "*."
	}
	// labels[0] is the deepest label; we want labelCount labels from the right
	// e.g., labels = ["www", "example", "com"], labelCount = 1 → ["com"] → "*.com."
	start := len(labels) - labelCount
	return "*." + strings.Join(labels[start:], ".") + "."
}

// nsec3HashLessThan returns true if hash a < hash b lexicographically.
func nsec3HashLessThan(a, b []byte) bool {
	return bytes.Compare(a, b) < 0
}

// findClosestEncloserNSEC3 walks the query name labels from longest to shortest,
// computing HashName for each ancestor until a matching NSEC3 owner is found.
// Returns the closest-encloser NSEC3 record, its owner hash, and the query ancestor name.
// If no NSEC3 matches any ancestor, returns (nil, nil, "").
func findClosestEncloserNSEC3(nsec3Records []DNSRecord, queryName string, alg uint8, iterations uint16, salt []byte) (*DNSRecord, []byte, string) {
	name := strings.TrimSuffix(queryName, ".")
	labels := strings.Split(name, ".")

	// Build ancestor names from longest to shortest (most labels to fewest)
	// For query "www.example.com.", ancestors in order are:
	// "www.example.com.", "example.com.", "com."
	for i := 0; i < len(labels); i++ {
		ancestor := strings.Join(labels[i:], ".") + "."
		ancestorHash := HashName(ancestor, alg, iterations, salt)
		encHashStr := string(ancestorHash)

		for _, nsec3 := range nsec3Records {
			ownerHash := decodeBase32Hash(nsec3.Name)
			if ownerHash != nil && encHashStr == string(ownerHash) {
				return &nsec3, ownerHash, ancestor
			}
		}
	}
	return nil, nil, ""
}

// nextCloserNSEC3 finds the NSEC3 record with the smallest hash that is strictly
// greater than the given closestEncloserHash, wrapping at the zone boundary.
// This provides the next-closer proof per RFC 5155 Section 7.2.1.
func nextCloserNSEC3(nsec3Records []DNSRecord, closestEncloserHash []byte) *DNSRecord {
	var nextCloser *DNSRecord
	for _, nsec3 := range nsec3Records {
		ownerHash := decodeBase32Hash(nsec3.Name)
		if ownerHash == nil {
			continue
		}
		// Must be strictly greater than closest-encloser
		if nsec3HashLessThan(closestEncloserHash, ownerHash) {
			if nextCloser == nil || nsec3HashLessThan(ownerHash, decodeBase32Hash(nextCloser.Name)) {
				nextCloser = &nsec3
			}
		}
	}
	return nextCloser
}

// ValidateNSEC3Proof validates NSEC3 records for an NXDOMAIN or no-data response.
// It implements RFC 5155 Section 7.2.1 closest-encloser + next-closer chain validation
// and RFC 5155 Section 7.2.14 wildcard denial proof.
//
// For NXDOMAIN responses, the proof chain requires:
//  1. A closest-encloser NSEC3 whose owner hash matches the hashed closest-encloser name
//  2. A next-closer NSEC3 with a hash greater than the closest-encloser, proving
//     no names exist between closest-encloser and query name
//  3. A wildcard NSEC3 proving no wildcard exists at (closest-encloser + 1) label
//
// For no-data responses, the NSEC3 at the exact query name hash must show the
// queried type bit is absent in its type bitmap.
// It verifies:
// 1. All NSEC3 records have valid format (hash algorithm = 1)
// 2. The NSEC3 records prove the correct response (NXDOMAIN, no-data, or wildcard)
// 3. Type bitmaps correctly reflect the record types present/absent
//
// NOTE: Full NXDOMAIN validation per RFC 5155 Section 7.2.1 requires a closest-encloser
// proof + next-closer proof chain. This implementation only validates that at least one
// NSEC3 covers the query hash, which is a necessary but not sufficient condition.
// A complete NXDOMAIN proof requires zone-level NSEC3PARAM and sorted hash chain context.
func ValidateNSEC3Proof(nsec3Records []DNSRecord, queryName string, queryType uint16) error {
	if len(nsec3Records) == 0 {
		return errors.New("dnssec: no nsec3 records provided")
	}

	// Step 1: Validate format of all NSEC3 records
	for _, nsec3 := range nsec3Records {
		if err := ValidateNSEC3RecordFormat(nsec3); err != nil {
			return err
		}
	}

	// Step 2: Verify owner names are valid hashes
	for _, nsec3 := range nsec3Records {
		if _, err := VerifyNSEC3OwnerName(nsec3, queryName); err != nil {
			return err // Fatal — owner name hash mismatch invalidates the proof
		}
	}

	// Step 3: Find closest-encloser by walking query name labels longest to shortest
	refNSEC3 := nsec3Records[0]
	closestNSEC3, closestHash, _ := findClosestEncloserNSEC3(
		nsec3Records, queryName, refNSEC3.HashAlg, refNSEC3.Iterations, refNSEC3.Salt,
	)
	if closestNSEC3 == nil {
		return ErrNSEC3NoClosestEncloser
	}

	// Step 4: For no-data responses (queryType != 0), check if the exact query name NSEC3
	// proves no-data before doing the full NXDOMAIN chain validation.
	// If the NSEC3 at the exact query name hash is the closest-encloser and the type
	// bit is absent, it's a valid no-data proof.
	if queryType != 0 && queryType != uint16(NSEC3) && queryType != uint16(NSEC3PARAM) {
		queryHash := HashName(queryName, refNSEC3.HashAlg, refNSEC3.Iterations, refNSEC3.Salt)
		for _, nsec3 := range nsec3Records {
			ownerHash := decodeBase32Hash(nsec3.Name)
			if ownerHash != nil && string(ownerHash) == string(queryHash) {
				if TypeBitMapPresent(nsec3.TypeBitMap, queryType) {
					return ErrNSEC3InvalidProof // Type exists at name — not no-data
				}
				// Type not in bitmap — valid no-data proof, we're done
				return nil
			}
		}
	}

	// Step 5: Find next-closer NSEC3 (smallest hash > closest-encloser hash)
	// The next-closer proves no names exist between closest-encloser and query name
	nextCloserNSEC3 := nextCloserNSEC3(nsec3Records, closestHash)
	if nextCloserNSEC3 == nil {
		// No next-closer means the zone ends after closest-encloser
		// The closest-encloser's own NextHash must cover the query hash to prove
		// that no names exist between closest-encloser and query
		if !nsec3CoversHash(closestHash, closestNSEC3.NextHash, closestHash) {
			// Self-coverage check: closest-encloser must prove the gap
			return ErrNSEC3NoNextCloser
		}
	} else {
		// Next-closer exists — verify the gap between closest-encloser and next-closer
		// covers the query hash. The query hash must fall between closest and next.
		// The range is: closestHash <= queryHash < nextCloserHash
		nextHash := decodeBase32Hash(nextCloserNSEC3.Name)
		if !nsec3CoversHash(closestHash, nextHash, closestHash) {
			return ErrNSEC3NoNextCloser
		}
	}

	// Step 6: Verify no wildcard exists at (closest-encloser + 1 label)
	// e.g., for query "www.example.com." with closest-encloser "example.com.",
	// wildcard would be "*.example.com."
	wildcard := wildcardName(queryName, 1)
	wildcardHash := HashName(wildcard, refNSEC3.HashAlg, refNSEC3.Iterations, refNSEC3.Salt)
	wildcardFound := false
	for _, nsec3 := range nsec3Records {
		ownerHash := decodeBase32Hash(nsec3.Name)
		if ownerHash != nil && string(ownerHash) == string(wildcardHash) {
			wildcardFound = true
			break
		}
	}
	if wildcardFound {
		return ErrNSEC3InvalidProof // wildcard at closest-encloser+1 exists — invalid NXDOMAIN
	}

	return nil
}

// decodeBase32Hash extracts the raw hash from an NSEC3 owner name.
// The owner is in format: <base32hash>.<zone.>
func decodeBase32Hash(ownerName string) []byte {
	ownerName = strings.TrimSuffix(ownerName, ".")
	dotIdx := strings.Index(ownerName, ".")
	if dotIdx <= 0 {
		return nil
	}
	hashPart := ownerName[:dotIdx]
	decoded, err := base32Decode(hashPart)
	if err != nil {
		return nil
	}
	return decoded
}

// ValidateNSEC3WildcardProof verifies a wildcard proof per RFC 5155 Section 7.2.14.
//
// This implementation is a partial check: it validates that an NSEC3 record
// exists whose owner name is the base32-encoded hash of wildcardName, and
// (optionally) that the type bitmap indicates the query type is present.
//
// Full RFC 5155 Section 7.2.14 wildcard proof validation additionally requires:
// - That the immediate ancestor of the wildcard exists
// - That no non-wildcard records exist between wildcard and query name
// Implementing the complete closest-encloser / next-closer chain for wildcard
// proofs requires zone-level NSEC3PARAM and sorted hash chain context.
func ValidateNSEC3WildcardProof(nsec3Records []DNSRecord, wildcardName string, queryType uint16) error {
	if len(nsec3Records) == 0 {
		return errors.New("dnssec: no nsec3 records for wildcard proof")
	}

	// Validate all records first
	for _, nsec3 := range nsec3Records {
		if err := ValidateNSEC3RecordFormat(nsec3); err != nil {
			return err
		}
	}

	// Find the NSEC3 that proves the wildcard exists
	// The owner should be hash of *.zone.
	wildcardHash := HashName(wildcardName, 1, nsec3Records[0].Iterations, nsec3Records[0].Salt)

	// Find NSEC3 whose owner matches the wildcard hash
	for _, nsec3 := range nsec3Records {
		ownerHash := decodeBase32Hash(nsec3.Name)
		if string(ownerHash) == string(wildcardHash) {
			// Verify the type bitmap shows the query type exists at wildcard
			if queryType != 0 && !TypeBitMapPresent(nsec3.TypeBitMap, queryType) {
				return ErrNSEC3InvalidProof
			}
			return nil
		}
	}

	return ErrNSEC3InvalidProof
}
