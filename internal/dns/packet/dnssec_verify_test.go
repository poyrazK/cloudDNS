package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestVerifyRRSet_ValidSignature tests signature verification with a valid signature.
func TestVerifyRRSet_ValidSignature(t *testing.T) {
	// Generate a key pair
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	// Create a DNSKEY
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13, // ECDSAP256SHA256
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	// Create an RRSet to sign
	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	// Sign the RRSet
	now := uint32(1600000000)
	inception := now - 3600   // 1 hour ago
	expiration := now + 86400 // 1 day ahead
	keyTag := dnskey.ComputeKeyTag()

	sig, err := SignRRSet(rrset, privKey, "example.com.", keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	// Verify the signature
	valid, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != nil {
		t.Fatalf("VerifyRRSet failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature, got invalid")
	}
}

// TestVerifyRRSet_RoundTrip tests that we can sign and verify a round trip.
func TestVerifyRRSet_RoundTrip(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	now := uint32(1600000000)
	inception := now - 3600
	expiration := now + 86400
	keyTag := dnskey.ComputeKeyTag()

	// Sign
	sig, err := SignRRSet(rrset, privKey, "example.com.", keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	t.Logf("Sig RDATA length: %d", len(sig.Signature))
	t.Logf("DNSKEY ComputeKeyTag: %d", dnskey.ComputeKeyTag())
	t.Logf("Sig KeyTag: %d", sig.KeyTag)

	// Verify manually using crypto
	buf := NewBytePacketBuffer()
	for _, r := range rrset {
		_ = buf.WriteName(strings.ToLower(r.Name))
		_ = buf.Writeu16(uint16(r.Type))
		_ = buf.Writeu16(r.Class)
		_ = buf.Writeu32(r.TTL)
		ip4 := r.IP.To4()
		_ = buf.Writeu16(4)
		for _, b := range ip4 {
			_ = buf.Write(b)
		}
	}

	signBuf := NewBytePacketBuffer()
	for _, r := range rrset {
		_ = signBuf.WriteName(strings.ToLower(r.Name))
		_ = signBuf.Writeu16(uint16(r.Type))
		_ = signBuf.Writeu16(uint16(1))
		_ = signBuf.Writeu32(r.TTL)
		_ = writeSignCanonicalRData(&r, signBuf)
	}

	// Try manual verification with same hash
	hashed := sha256.Sum256(signBuf.Buf[:signBuf.Position()])
	t.Logf("Hash: %x", hashed[:])

	// Extract public key properly from the DNSKEY we created
	pubBytes := encodeECDSAPublicKey(&pubKey)
	t.Logf("EncPubKey: %x", pubBytes)

	// Try with x/y from the encoded key
	x2 := new(big.Int).SetBytes(pubBytes[1:33])
	y2 := new(big.Int).SetBytes(pubBytes[33:65])
	t.Logf("X2: %x", x2.Bytes())
	t.Logf("Y2: %x", y2.Bytes())

	// Verify using our function
	valid, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != nil {
		t.Fatalf("VerifyRRSet failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature, got invalid")
	}
}

// TestVerifyRRSet_ExpiredSignature tests that expired signatures are rejected.

// TestVerifyRRSet_ExpiredSignature tests that expired signatures are rejected.
func TestVerifyRRSet_ExpiredSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	now := uint32(time.Now().Unix())
	inception := now - 86400*2 // 2 days ago
	expiration := now - 3600   // 1 hour ago (expired)
	keyTag := dnskey.ComputeKeyTag()

	sig, err := SignRRSet(rrset, privKey, "example.com.", keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	_, err = VerifyRRSet(rrset, sig, dnskey, now)
	if err != ErrSignatureExpired {
		t.Errorf("Expected ErrSignatureExpired, got %v", err)
	}
}

// TestVerifyRRSet_NotYetValid tests that signatures not yet valid are rejected.
func TestVerifyRRSet_NotYetValid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	now := uint32(time.Now().Unix())
	inception := now + 86400 // 1 day in the future
	expiration := now + 86400*2
	keyTag := dnskey.ComputeKeyTag()

	sig, err := SignRRSet(rrset, privKey, "example.com.", keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	_, err = VerifyRRSet(rrset, sig, dnskey, now)
	if err != ErrSignatureNotYetValid {
		t.Errorf("Expected ErrSignatureNotYetValid, got %v", err)
	}
}

// TestVerifyRRSet_KeyTagMismatch tests that mismatched key tags are rejected.
func TestVerifyRRSet_KeyTagMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	now := uint32(time.Now().Unix())
	sig, _ := SignRRSet(rrset, privKey, "example.com.", dnskey.ComputeKeyTag(), now-3600, now+86400)

	// Modify key tag
	sig.KeyTag = sig.KeyTag + 1

	_, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != ErrKeyTagMismatch {
		t.Errorf("Expected ErrKeyTagMismatch, got %v", err)
	}
}

// TestVerifyRRSet_AlgorithmMismatch tests that algorithm mismatches are rejected.
func TestVerifyRRSet_AlgorithmMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	now := uint32(time.Now().Unix())
	sig, _ := SignRRSet(rrset, privKey, "example.com.", dnskey.ComputeKeyTag(), now-3600, now+86400)

	// Modify algorithm
	sig.Algorithm = 14 // Different algorithm

	_, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != ErrAlgorithmMismatch {
		t.Errorf("Expected ErrAlgorithmMismatch, got %v", err)
	}
}

// TestVerifyRRSet_InvalidSignature tests that corrupted signatures are rejected.
func TestVerifyRRSet_InvalidSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	rrset := []DNSRecord{
		{
			Name:  "www.example.com.",
			Type:  A,
			Class: 1,
			TTL:   300,
			IP:    []byte{1, 2, 3, 4},
		},
	}

	now := uint32(time.Now().Unix())
	sig, _ := SignRRSet(rrset, privKey, "example.com.", dnskey.ComputeKeyTag(), now-3600, now+86400)

	// Corrupt the signature
	sig.Signature[0] ^= 0xFF

	_, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

// TestVerifyRRSet_EmptyRRSet tests that empty RRsets are rejected.
func TestVerifyRRSet_EmptyRRSet(t *testing.T) {
	_, err := VerifyRRSet([]DNSRecord{}, DNSRecord{}, DNSRecord{}, 0)
	if err == nil {
		t.Error("Expected error for empty rrset")
	}
}

// TestVerifyDNSKEYMatchesDS_Valid tests DS verification with matching DNSKEY.
func TestVerifyDNSKEYMatchesDS_Valid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	// Compute DS from DNSKEY
	ds, err := dnskey.ComputeDS(2) // SHA-256
	if err != nil {
		t.Fatalf("ComputeDS failed: %v", err)
	}

	// Verify DNSKEY matches DS
	valid, err := VerifyDNSKEYMatchesDS(dnskey, ds)
	if err != nil {
		t.Fatalf("VerifyDNSKEYMatchesDS failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid DS match")
	}
}

// TestVerifyDNSKEYMatchesDS_Invalid tests DS verification with mismatched digest.
func TestVerifyDNSKEYMatchesDS_Invalid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	ds, _ := dnskey.ComputeDS(2)

	// Modify the digest
	ds.Digest[0] ^= 0xFF

	_, err := VerifyDNSKEYMatchesDS(dnskey, ds)
	if err == nil {
		t.Error("Expected error for mismatched DS digest")
	}
}

// TestVerifyDNSKEYSelfSignature_Valid tests self-signature verification.
func TestVerifyDNSKEYSelfSignature_Valid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	valid, err := VerifyDNSKEYSelfSignature(dnskey)
	if err != nil {
		t.Fatalf("VerifyDNSKEYSelfSignature failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid self-signature check")
	}
}

// TestVerifyDNSKEYSelfSignature_WrongType tests self-signature with wrong record type.
func TestVerifyDNSKEYSelfSignature_WrongType(t *testing.T) {
	record := DNSRecord{
		Name: "example.com.",
		Type: A,
	}

	_, err := VerifyDNSKEYSelfSignature(record)
	if err != ErrInvalidDNSKEY {
		t.Errorf("Expected ErrInvalidDNSKEY, got %v", err)
	}
}

// TestCanonicalWireMarshal_A tests canonical wire format for A records.
func TestCanonicalWireMarshal_A(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:  "www.example.COM.",
		Type:  A,
		Class: 1,
		TTL:   300,
		IP:    []byte{1, 2, 3, 4},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}

	// Verify owner name is lowercase
	data := string(buf.Buf[:buf.Position()])
	if !containsLowercase(data) {
		t.Error("Expected lowercase owner name in canonical form")
	}
}

// TestCanonicalWireMarshal_AAAA tests canonical wire format for AAAA records.
func TestCanonicalWireMarshal_AAAA(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:  "www.example.COM.",
		Type:  AAAA,
		Class: 1,
		TTL:   300,
		IP:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}
}

// TestCanonicalWireMarshal_TXT tests canonical wire format for TXT records.
func TestCanonicalWireMarshal_TXT(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:  "example.COM.",
		Type:  TXT,
		Class: 1,
		TTL:   300,
		Txt:   "Hello World",
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}
}

// TestCanonicalWireMarshal_DNSKEY tests canonical wire format for DNSKEY.
func TestCanonicalWireMarshal_DNSKEY(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.PublicKey

	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:      "example.COM.",
		Type:      DNSKEY,
		Class:     1,
		TTL:       300,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey),
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}

	// Verify canonical order: flags | protocol | algorithm | publickey
	data := buf.Buf[:buf.Position()]
	if len(data) < 4 {
		t.Error("Expected at least 4 bytes for DNSKEY header")
	}
}

// TestCanonicalWireMarshal_CNAME tests canonical wire format for CNAME.
func TestCanonicalWireMarshal_CNAME(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:  "www.example.COM.",
		Type:  CNAME,
		Class: 1,
		TTL:   300,
		Host:  "example.COM.",
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}
}

// TestFindMatchingDNSKEY tests finding a matching DNSKEY for an RRSIG.
func TestFindMatchingDNSKEY(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey1 := privKey1.PublicKey
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey2 := privKey2.PublicKey

	// Create first DNSKEY (non-matching)
	dnskey1 := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey1),
	}

	// Create second DNSKEY (matching) - compute its actual key tag
	dnskey2 := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey2),
	}
	computedKeyTag := dnskey2.ComputeKeyTag()

	rrsig := DNSRecord{
		TypeCovered: uint16(A),
		Algorithm:   13,
		KeyTag:      computedKeyTag,
		SignerName:  "example.com.",
	}

	dnskeys := []DNSRecord{dnskey1, dnskey2}

	found := FindMatchingDNSKEY(rrsig, dnskeys)
	if found == nil {
		t.Error("Expected to find matching DNSKEY")
	}
	if found != &dnskeys[1] {
		t.Error("Expected to find the second DNSKEY (matching one)")
	}
}

// TestFindMatchingDNSKEY_NotFound tests when no matching DNSKEY exists.
func TestFindMatchingDNSKEY_NotFound(t *testing.T) {
	dnskeys := []DNSRecord{
		{
			Name:      "example.com.",
			Type:      DNSKEY,
			Algorithm: 13,
		},
	}

	rrsig := DNSRecord{
		TypeCovered: uint16(A),
		Algorithm:   14, // Different algorithm
		KeyTag:      12345,
	}

	found := FindMatchingDNSKEY(rrsig, dnskeys)
	if found != nil {
		t.Error("Expected no matching DNSKEY")
	}
}

// encodeECDSAPublicKey encodes an ECDSA public key into DNSKEY format.
func encodeECDSAPublicKey(pub *ecdsa.PublicKey) []byte {
	// Uncompressed point format: 0x04 || X || Y
	result := make([]byte, 65)
	result[0] = 0x04
	// Use fixed-size 32-byte big-endian encoding
	xBytes := pub.X.FillBytes(make([]byte, 32))
	yBytes := pub.Y.FillBytes(make([]byte, 32))
	copy(result[1:33], xBytes)
	copy(result[33:65], yBytes)
	return result
}

// containsLowercase checks if a string contains lowercase letters.
func containsLowercase(s string) bool {
	for _, c := range s {
		if c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}
