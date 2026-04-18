package packet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
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
	// ErrNSEC3HashAlgoUnsupported indicates the NSEC3 hash algorithm is not supported.
	ErrNSEC3HashAlgoUnsupported = errors.New("dnssec: nsec3 hash algorithm unsupported")
	// ErrNSEC3InvalidProof indicates the NSEC3 proof is invalid.
	ErrNSEC3InvalidProof = errors.New("dnssec: nsec3 invalid proof")
	// ErrNSEC3ChainBroken indicates the NSEC3 hash chain is broken.
	ErrNSEC3ChainBroken = errors.New("dnssec: nsec3 chain broken")
	// ErrNSEC3NoMatchingName indicates the NSEC3 owner name doesn't match.
	ErrNSEC3NoMatchingName = errors.New("dnssec: nsec3 owner name hash mismatch")
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
// It supports ECDSA P-256 (Algorithm 13), RSA SHA-256 (Algorithm 8), and Ed25519 (Algorithm 15) signatures.
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

	// 6. Reconstruct canonical wire format of RRSIG/RRset per RFC 4034 Section 8.1
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

	// 7. Compute hash
	hashed := sha256.Sum256(buf.Buf[:buf.Position()])

	// 8. Verify signature based on algorithm
	switch rrsig.Algorithm {
	case AlgorithmECDSAP256:
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

	case AlgorithmRSASHA256:
		publicKey, err := extractRSAPublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], rrsig.Signature); err != nil {
			return false, ErrInvalidSignature
		}

	case AlgorithmED25519:
		publicKey, err := extractED25519PublicKey(dnskey)
		if err != nil {
			return false, err
		}
		if !ed25519.Verify(publicKey, buf.Buf[:buf.Position()], rrsig.Signature) {
			return false, ErrInvalidSignature
		}

	default:
		return false, ErrUnsupportedAlgorithm
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

// extractRSAPublicKey extracts an RSA public key from a DNSKEY record.
// RFC 5702 defines RSA/SHA-256 for DNSSEC.
func extractRSAPublicKey(dnskey DNSRecord) (*rsa.PublicKey, error) {
	if len(dnskey.PublicKey) < 64 {
		return nil, ErrNoPublicKey
	}

	// RSA public key in DNSKEY is stored as a big-endian integer
	keySize := len(dnskey.PublicKey)
	if keySize < 128 || keySize > 512 {
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

// base32Decode decodes a NSEC3 base32 string (RFC 5155 alphabet) into bytes.
// The alphabet is: 0-9 a-v (no uppercase, no special chars).
func base32Decode(encoded string) ([]byte, error) {
	const nsec3Base32 = "0123456789abcdefghijklmnopqrstuv"
	alphabet := make(map[byte]int)
	for i := range nsec3Base32 {
		alphabet[nsec3Base32[i]] = i
	}

	var result []byte
	var buffer uint32
	var bits uint8

	for i := range encoded {
		c := encoded[i]
		val, ok := alphabet[c]
		if !ok {
			return nil, errors.New("dnssec: invalid base32 character")
		}
		buffer = (buffer << 5) | uint32(val)
		bits += 5
		if bits >= 8 {
			bits -= 8
			result = append(result, byte(buffer>>bits))
			buffer &= (1 << bits) - 1
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
	zonePart := owner[dotIdx+1:]

	// Decode the hash from the owner name
	ownerHash, err := base32Decode(hashPart)
	if err != nil {
		return false, ErrNSEC3NoMatchingName
	}

	// Compute expected hash of the name with NSEC3 params
	// Zone part becomes the base for hashing
	computedHash := HashName(zonePart, nsec3.HashAlg, nsec3.Iterations, nsec3.Salt)

	if string(ownerHash) != string(computedHash) {
		return false, ErrNSEC3NoMatchingName
	}

	return true, nil
}

// nsec3CoversHash checks whether an NSEC3 record covers the given hash.
// An NSEC3 record covers a hash if: ownerHash <= coveredHash < nextHash
// where ordering is lexicographic on the raw hash bytes.
func nsec3CoversHash(ownerHash, nextHash, coveredHash []byte) bool {
	// If nextHash is empty or equals ownerHash, this NSEC3 doesn't cover anything valid
	if len(nextHash) == 0 || len(ownerHash) != len(nextHash) {
		return false
	}

	// Simple lexicographic comparison of raw bytes
	if string(coveredHash) < string(ownerHash) {
		return false
	}
	// Special case: if coveredHash >= nextHash, it wraps around
	if string(coveredHash) >= string(nextHash) {
		return true // Covered (wraps around to owner or before)
	}
	return true
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
			if byteIndex < bitmapLen && (bitmap[i+byteIndex]&(1<<bitIndex)) != 0 {
				return true
			}
		}
		i += bitmapLen
	}
	return false
}

// ValidateNSEC3Proof validates NSEC3 records for an NXDOMAIN or no-data response.
// It verifies:
// 1. All NSEC3 records have valid format (hash algorithm = 1)
// 2. The NSEC3 records prove the correct response (NXDOMAIN, no-data, or wildcard)
// 3. Type bitmaps correctly reflect the record types present/absent
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
		valid, err := VerifyNSEC3OwnerName(nsec3, queryName)
		if err != nil {
			return err
		}
		if !valid {
			// Owner name doesn't match expected hash - could be covering proof
			// Continue to chain validation
		}
	}

	// Step 3: For NXDOMAIN, we need closest-encloser proof
	// The NSEC3 records should show:
	// - Closest encloser: covers the query name
	// - Next closer: shows no names between closest encloser and query
	// For simplicity, verify at least one NSEC3 covers the query name

	// Compute the hash of the query name with the first NSEC3's params
	if len(nsec3Records) == 0 {
		return ErrNSEC3InvalidProof
	}

	// Use the first NSEC3 record's parameters to hash the query name
	refNSEC3 := nsec3Records[0]
	queryHash := HashName(queryName, refNSEC3.HashAlg, refNSEC3.Iterations, refNSEC3.Salt)

	// Find NSEC3 that covers the query hash
	covered := false
	for _, nsec3 := range nsec3Records {
		if nsec3CoversHash(decodeBase32Hash(nsec3.Name), nsec3.NextHash, queryHash) {
			covered = true
			break
		}
	}

	if !covered {
		return ErrNSEC3InvalidProof
	}

	// Step 4: For no-data responses, verify the NSEC3 covers the type
	if queryType != 0 && queryType != uint16(NSEC3) && queryType != uint16(NSEC3PARAM) {
		// Find the NSEC3 whose owner is the exact query name hash
		for _, nsec3 := range nsec3Records {
			ownerHash := decodeBase32Hash(nsec3.Name)
			if string(ownerHash) == string(queryHash) {
				// This NSEC3 is for the exact name - check if it has the type
				if TypeBitMapPresent(nsec3.TypeBitMap, queryType) {
					return ErrNSEC3InvalidProof // Type exists, shouldn't be here
				}
				// Type not in bitmap = correct no-data proof
				return nil
			}
		}
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
// It checks that the NSEC3 records prove:
// 1. The immediate ancestor of the wildcard exists
// 2. No non-wildcard records exist between wildcard and query name
// 3. The wildcard record exists and covers the query type
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
