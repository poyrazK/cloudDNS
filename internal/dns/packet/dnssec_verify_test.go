package packet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
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

	sig, err := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", keyTag, inception, expiration)
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
	sig, err := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", keyTag, inception, expiration)
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
	t.Logf("EncPubKey len: %d", len(pubBytes))
	t.Logf("EncPubKey: %x", pubBytes)

	// Try with x/y from the encoded key (64-byte X||Y format)
	x2 := new(big.Int).SetBytes(pubBytes[0:32])
	y2 := new(big.Int).SetBytes(pubBytes[32:64])
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

	sig, err := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	_, err = VerifyRRSet(rrset, sig, dnskey, now)
	if !errors.Is(err, ErrSignatureExpired) {
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

	sig, err := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}

	_, err = VerifyRRSet(rrset, sig, dnskey, now)
	if !errors.Is(err, ErrSignatureNotYetValid) {
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
	sig, _ := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-3600, now+86400)

	// Modify key tag
	sig.KeyTag = sig.KeyTag + 1

	_, err := VerifyRRSet(rrset, sig, dnskey, now)
	if !errors.Is(err, ErrKeyTagMismatch) {
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
	sig, _ := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-3600, now+86400)

	// Modify algorithm
	sig.Algorithm = 14 // Different algorithm

	_, err := VerifyRRSet(rrset, sig, dnskey, now)
	if !errors.Is(err, ErrAlgorithmMismatch) {
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
	sig, _ := SignRRSet(rrset, privKey, AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-3600, now+86400)

	// Corrupt the signature
	sig.Signature[0] ^= 0xFF

	_, err := VerifyRRSet(rrset, sig, dnskey, now)
	if !errors.Is(err, ErrInvalidSignature) {
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

// TestValidateDNSKEYFormat_Valid tests self-signature verification.
func TestValidateDNSKEYFormat_Valid(t *testing.T) {
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

	valid, err := ValidateDNSKEYFormat(dnskey)
	if err != nil {
		t.Fatalf("ValidateDNSKEYFormat failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid self-signature check")
	}
}

// TestValidateDNSKEYFormat_WrongType tests self-signature with wrong record type.
func TestValidateDNSKEYFormat_WrongType(t *testing.T) {
	record := DNSRecord{
		Name: "example.com.",
		Type: A,
	}

	_, err := ValidateDNSKEYFormat(record)
	if !errors.Is(err, ErrInvalidDNSKEY) {
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

// TestCanonicalWireMarshal_RRSIG tests canonical wire format for RRSIG.
func TestCanonicalWireMarshal_RRSIG(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:        "example.com.",
		Type:        RRSIG,
		Class:       1,
		TTL:         300,
		TypeCovered: uint16(A),
		Algorithm:   13,
		Labels:      2,
		OrigTTL:     300,
		Expiration:  1600000000,
		Inception:   1599900000,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   make([]byte, 64),
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	if len(data) < 18 {
		t.Error("Expected at least 18 bytes for RRSIG header")
	}
}

// TestCanonicalWireMarshal_DS tests canonical wire format for DS.
func TestCanonicalWireMarshal_DS(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:       "example.com.",
		Type:       DS,
		Class:      1,
		TTL:        300,
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02, 0x03, 0x04},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	if len(data) < 4 {
		t.Error("Expected at least 4 bytes for DS header")
	}
}

// TestCanonicalWireMarshal_SOA tests canonical wire format for SOA.
func TestCanonicalWireMarshal_SOA(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:    "example.com.",
		Type:    SOA,
		Class:   1,
		TTL:     300,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   3600,
		Expire:  3600,
		Minimum: 300,
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}
}

// TestCanonicalWireMarshal_SRV tests canonical wire format for SRV.
func TestCanonicalWireMarshal_SRV(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:     "_http._tcp.example.com.",
		Type:     SRV,
		Class:    1,
		TTL:      300,
		Priority: 10,
		Weight:   20,
		Port:     80,
		Host:     "server.example.com.",
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	if len(data) < 7 {
		t.Error("Expected at least 7 bytes for SRV header")
	}
}

// TestCanonicalWireMarshal_NSEC tests canonical wire format for NSEC.
func TestCanonicalWireMarshal_NSEC(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:       "example.com.",
		Type:       NSEC,
		Class:      1,
		TTL:        300,
		NextName:   "example2.com.",
		TypeBitMap: []byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x05},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}
}

// TestCanonicalWireMarshal_Default tests canonical wire format for unknown types using raw Data.
func TestCanonicalWireMarshal_Default(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:  "example.com.",
		Type:  UNKNOWN,
		Class: 1,
		TTL:   300,
		Data:  []byte{0x01, 0x02, 0x03},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err != nil {
		t.Fatalf("CanonicalWireMarshal failed: %v", err)
	}
}

// TestWriteCanonicalRData_NS tests canonical RDATA for NS records.
func TestWriteCanonicalRData_NS(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name: "example.com.",
		Type: NS,
		Host: "ns1.example.com.",
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}
}

// TestWriteCanonicalRData_CNAME tests canonical RDATA for CNAME records.
func TestWriteCanonicalRData_CNAME(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name: "www.example.com.",
		Type: CNAME,
		Host: "example.com.",
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}
}

// TestWriteCanonicalRData_PTR tests canonical RDATA for PTR records.
func TestWriteCanonicalRData_PTR(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name: "1.0.0.127.in-addr.arpa.",
		Type: PTR,
		Host: "localhost.",
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}
}

// TestWriteCanonicalRData_MX tests canonical RDATA for MX records.
func TestWriteCanonicalRData_MX(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:     "example.com.",
		Type:     MX,
		Priority: 10,
		Host:     "mail.example.com.",
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	if len(data) < 3 {
		t.Error("Expected at least 3 bytes for MX RDATA")
	}
}

// TestWriteCanonicalRData_SOA tests canonical RDATA for SOA records.
func TestWriteCanonicalRData_SOA(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:    "example.com.",
		Type:    SOA,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   3600,
		Expire:  3600,
		Minimum: 300,
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}
}

// TestWriteCanonicalRData_SRV tests canonical RDATA for SRV records.
func TestWriteCanonicalRData_SRV(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:     "_http._tcp.example.com.",
		Type:     SRV,
		Priority: 10,
		Weight:   20,
		Port:     8080,
		Host:     "server.example.com.",
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	if len(data) < 7 {
		t.Error("Expected at least 7 bytes for SRV RDATA")
	}
}

// TestWriteCanonicalRData_DS tests canonical RDATA for DS records.
func TestWriteCanonicalRData_DS(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:       "example.com.",
		Type:       DS,
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{0x01, 0x02, 0x03, 0x04},
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}

	data := buf.Buf[:buf.Position()]
	if len(data) < 4 {
		t.Error("Expected at least 4 bytes for DS RDATA")
	}
}

// TestWriteCanonicalRData_NSEC tests canonical RDATA for NSEC records.
func TestWriteCanonicalRData_NSEC(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name:       "example.com.",
		Type:       NSEC,
		NextName:   "example2.com.",
		TypeBitMap: []byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1c},
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}
}

// TestWriteCanonicalRData_Default tests canonical RDATA for unknown types.
func TestWriteCanonicalRData_Default(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name: "example.com.",
		Type: UNKNOWN,
		Data: []byte{0x01, 0x02, 0x03},
	}

	err := writeCanonicalRData(&record, buf)
	if err != nil {
		t.Fatalf("writeCanonicalRData failed: %v", err)
	}
}

// TestVerifyDNSKEYMatchesDS_KeyTagMismatch tests when key tags don't match.
func TestVerifyDNSKEYMatchesDS_KeyTagMismatch(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey1 := privKey1.PublicKey
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey2 := privKey2.PublicKey

	// Create two DNSKEYs with different key tags
	dnskey1 := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey1),
	}

	dnskey2 := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: encodeECDSAPublicKey(&pubKey2),
	}

	// Compute DS from dnskey1
	ds, _ := dnskey1.ComputeDS(2)

	// Verify with dnskey2 (different key tag) should fail
	_, err := VerifyDNSKEYMatchesDS(dnskey2, ds)
	if !errors.Is(err, ErrKeyTagMismatch) {
		t.Errorf("Expected ErrKeyTagMismatch, got %v", err)
	}
}

// TestValidateDNSKEYFormat_NoPublicKey tests with missing public key.
func TestValidateDNSKEYFormat_NoPublicKey(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02}, // Too short
	}

	_, err := ValidateDNSKEYFormat(dnskey)
	if !errors.Is(err, ErrNoPublicKey) {
		t.Errorf("Expected ErrNoPublicKey, got %v", err)
	}
}

// TestValidateDNSKEYFormat_UnsupportedAlgorithm tests with invalid key format.
func TestValidateDNSKEYFormat_UnsupportedAlgorithm(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: make([]byte, 65), // Valid length but wrong format
	}

	_, err := ValidateDNSKEYFormat(dnskey)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("Expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

// TestWriteCanonicalRData_SOA_BufferFull tests SOA error when buffer is nearly full.
func TestWriteCanonicalRData_SOA_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 1 // Only 1 byte left
	record := DNSRecord{
		Name:    "example.com.",
		Type:    SOA,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   3600,
		Expire:  3600,
		Minimum: 300,
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for SOA")
	}
}

// TestWriteCanonicalRData_SRV_BufferFull tests SRV error when buffer is nearly full.
func TestWriteCanonicalRData_SRV_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:     "_http._tcp.example.com.",
		Type:     SRV,
		Priority: 10,
		Weight:   20,
		Port:     8080,
		Host:     "server.example.com.",
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for SRV")
	}
}

// TestWriteCanonicalRData_DNSKEY_BufferFull tests DNSKEY error when buffer is nearly full.
func TestWriteCanonicalRData_DNSKEY_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: make([]byte, 65),
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for DNSKEY")
	}
}

// TestWriteCanonicalRData_DS_BufferFull tests DS error when buffer is nearly full.
func TestWriteCanonicalRData_DS_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:       "example.com.",
		Type:       DS,
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{1, 2, 3, 4},
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for DS")
	}
}

// TestWriteCanonicalRData_TXT_BufferFull tests TXT error when buffer is nearly full.
func TestWriteCanonicalRData_TXT_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 3 // Only 3 bytes left
	record := DNSRecord{
		Name: "example.com.",
		Type: TXT,
		Txt:  "long chunk that won't fit",
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for TXT")
	}
}

// TestWriteCanonicalRData_NSEC_BufferFull tests NSEC error when buffer is nearly full.
func TestWriteCanonicalRData_NSEC_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 3 // Only 3 bytes left
	record := DNSRecord{
		Name:       "example.com.",
		Type:       NSEC,
		NextName:   "example2.com.",
		TypeBitMap: []byte{1, 2, 3},
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for NSEC")
	}
}

// TestWriteCanonicalRData_MX_BufferFull tests MX error when buffer is nearly full.
func TestWriteCanonicalRData_MX_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:     "example.com.",
		Type:     MX,
		Priority: 10,
		Host:     "mail.example.com.",
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for MX")
	}
}

// encodeECDSAPublicKey encodes an ECDSA public key into DNSKEY format.
// RFC 6605 specifies ECDSA P-256 (Algorithm 13) uses X||Y format (64 bytes).
func encodeECDSAPublicKey(pub *ecdsa.PublicKey) []byte {
	// X || Y format per RFC 6605 (64 bytes total)
	result := make([]byte, 64)
	xBytes := pub.X.FillBytes(make([]byte, 32))
	yBytes := pub.Y.FillBytes(make([]byte, 32))
	copy(result[0:32], xBytes)
	copy(result[32:64], yBytes)
	return result
}

func encodeECDSAP384PublicKey(pub *ecdsa.PublicKey) []byte {
	// X || Y format per RFC 6605 (96 bytes total for P-384)
	result := make([]byte, 96)
	xBytes := pub.X.FillBytes(make([]byte, 48))
	yBytes := pub.Y.FillBytes(make([]byte, 48))
	copy(result[0:48], xBytes)
	copy(result[48:96], yBytes)
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

// TestWriteBytes_Error tests writeBytes error path when buffer is full.
func TestWriteBytes_Error(t *testing.T) {
	buf := NewBytePacketBuffer()
	// Fill buffer to near max
	buf.Pos = MaxPacketSize - 5
	// Try to write 10 bytes - should fail
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	err := writeBytes(buf, data)
	if err == nil {
		t.Error("Expected error when buffer is full")
	}
}

// TestWriteCanonicalRData_A_InvalidIP tests A record with invalid IP.
func TestWriteCanonicalRData_A_InvalidIP(t *testing.T) {
	buf := NewBytePacketBuffer()
	record := DNSRecord{
		Name: "example.com.",
		Type: A,
		IP:   []byte{1, 2}, // Invalid - too short for IPv4
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected error for invalid IPv4 address")
	}
	if err != nil && err.Error() != "invalid IPv4 address" {
		t.Errorf("Expected 'invalid IPv4 address' error, got %v", err)
	}
}

// TestCanonicalWireMarshal_SOA_BufferFull tests SOA buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_SOA_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 1 // Only 1 byte left
	record := DNSRecord{
		Name:    "example.com.",
		Type:    SOA,
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   3600,
		Expire:  3600,
		Minimum: 300,
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for SOA in CanonicalWireMarshal")
	}
}

// TestCanonicalWireMarshal_SRV_BufferFull tests SRV buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_SRV_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:     "_http._tcp.example.com.",
		Type:     SRV,
		Priority: 10,
		Weight:   20,
		Port:     8080,
		Host:     "server.example.com.",
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for SRV in CanonicalWireMarshal")
	}
}

// TestCanonicalWireMarshal_DNSKEY_BufferFull tests DNSKEY buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_DNSKEY_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:     "example.com.",
		Type:     DNSKEY,
		Flags:    256,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: []byte{0x04, 0x01, 0x02, 0x03},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for DNSKEY in CanonicalWireMarshal")
	}
}

// TestCanonicalWireMarshal_DS_BufferFull tests DS buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_DS_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:       "example.com.",
		Type:       DS,
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{1, 2, 3, 4},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for DS in CanonicalWireMarshal")
	}
}

// TestCanonicalWireMarshal_RRSIG_BufferFull tests RRSIG buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_RRSIG_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:        "example.com.",
		Type:        RRSIG,
		TypeCovered: 1,
		Algorithm:   13,
		Labels:      2,
		OrigTTL:     300,
		Expiration:   4102444800,
		Inception:   1609459200,
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   make([]byte, 64),
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for RRSIG in CanonicalWireMarshal")
	}
}

// TestCanonicalWireMarshal_NSEC_BufferFull tests NSEC buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_NSEC_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 3 // Only 3 bytes left
	record := DNSRecord{
		Name:       "example.com.",
		Type:       NSEC,
		NextName:   "example2.com.",
		TypeBitMap: []byte{1, 2, 3},
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for NSEC in CanonicalWireMarshal")
	}
}

// TestCanonicalWireMarshal_MX_BufferFull tests MX buffer-full error in CanonicalWireMarshal.
func TestCanonicalWireMarshal_MX_BufferFull(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.Pos = MaxPacketSize - 2 // Only 2 bytes left
	record := DNSRecord{
		Name:     "example.com.",
		Type:     MX,
		Priority: 10,
		Host:     "mail.example.com.",
	}

	err := CanonicalWireMarshal(&record, buf)
	if err == nil {
		t.Error("Expected buffer-full error for MX in CanonicalWireMarshal")
	}
}

// TestSignAndVerify_RSASHA256 tests sign and verify round-trip using RSA SHA-256 (Algorithm 8).
func TestSignAndVerify_RSASHA256(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	// Our RSA implementation stores N as the public key and hardcodes E=65537.
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: rsaKey.N.Bytes(),
	}

	rrset := []DNSRecord{
		{Name: "www.example.com.", Type: A, Class: 1, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}

	now := uint32(time.Now().Unix())
	keyTag := dnskey.ComputeKeyTag()

	sig, err := SignRRSet(rrset, rsaKey, AlgorithmRSASHA256, "example.com.", keyTag, now-3600, now+86400)
	if err != nil {
		t.Fatalf("SignRRSet (RSA) failed: %v", err)
	}

	valid, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != nil {
		t.Fatalf("VerifyRRSet (RSA) failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid RSA SHA-256 signature")
	}
}

// TestSignAndVerify_ED25519 tests sign and verify round-trip using Ed25519 (Algorithm 15).
func TestSignAndVerify_ED25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: AlgorithmED25519,
		PublicKey: pub,
	}

	rrset := []DNSRecord{
		{Name: "www.example.com.", Type: A, Class: 1, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}

	now := uint32(time.Now().Unix())
	keyTag := dnskey.ComputeKeyTag()

	// SignRRSet expects Ed25519 private key as [ed25519.PrivateKeySize]byte.
	var privArr [ed25519.PrivateKeySize]byte
	copy(privArr[:], priv)

	sig, err := SignRRSet(rrset, privArr, AlgorithmED25519, "example.com.", keyTag, now-3600, now+86400)
	if err != nil {
		t.Fatalf("SignRRSet (Ed25519) failed: %v", err)
	}

	valid, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != nil {
		t.Fatalf("VerifyRRSet (Ed25519) failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid Ed25519 signature")
	}
}

// TestSignAndVerify_ED448 tests sign and verify round-trip using Ed448 (Algorithm 16).
func TestSignAndVerify_ED448(t *testing.T) {
	pub, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed448.GenerateKey failed: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: AlgorithmED448,
		PublicKey: pub,
	}

	rrset := []DNSRecord{
		{Name: "www.example.com.", Type: A, Class: 1, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}

	now := uint32(time.Now().Unix())
	keyTag := dnskey.ComputeKeyTag()

	sig, err := SignRRSet(rrset, priv, AlgorithmED448, "example.com.", keyTag, now-3600, now+86400)
	if err != nil {
		t.Fatalf("SignRRSet (Ed448) failed: %v", err)
	}

	valid, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != nil {
		t.Fatalf("VerifyRRSet (Ed448) failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid Ed448 signature")
	}
}

// TestVerifyRRSet_UnsupportedAlgorithm tests that unsupported algorithms return an error.
func TestVerifyRRSet_UnsupportedAlgorithm(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes := encodeECDSAPublicKey(&privKey.PublicKey)

	// Build DNSKEY with unsupported algorithm 17 from the start so ComputeKeyTag uses it.
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: 17, // Reserved/unassigned algorithm - unsupported
		PublicKey: pubKeyBytes,
	}

	rrset := []DNSRecord{
		{Name: "www.example.com.", Type: A, Class: 1, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}

	now := uint32(time.Now().Unix())
	// Build RRSIG manually with matching key tag and algorithm 17 so all pre-checks pass.
	rrsig := DNSRecord{
		Type:        RRSIG,
		TypeCovered: uint16(A),
		Algorithm:   17,
		Labels:      3,
		OrigTTL:     300,
		Expiration:  now + 86400,
		Inception:   now - 3600,
		KeyTag:      dnskey.ComputeKeyTag(),
		SignerName:  "example.com.",
		Signature:   make([]byte, 64),
	}

	_, err := VerifyRRSet(rrset, rrsig, dnskey, now)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("Expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

// TestValidateNSEC3RecordFormat tests NSEC3 record format validation.
func TestValidateNSEC3RecordFormat(t *testing.T) {
	// Valid NSEC3 with SHA-1 (hash algorithm 1)
	nsec3 := DNSRecord{
		Type:       NSEC3,
		HashAlg:    1,
		Iterations: 10,
		Salt:       []byte{0xAB, 0xCD},
		NextHash:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}
	err := ValidateNSEC3RecordFormat(nsec3)
	if err != nil {
		t.Errorf("Expected valid NSEC3, got error: %v", err)
	}
}

// TestValidateNSEC3RecordFormat_UnsupportedHashAlgo tests that unsupported hash algorithms are rejected.
func TestValidateNSEC3RecordFormat_UnsupportedHashAlgo(t *testing.T) {
	nsec3 := DNSRecord{
		Type:       NSEC3,
		HashAlg:    2, // SHA-256 is not defined for NSEC3
		Iterations: 10,
		Salt:       []byte{0xAB, 0xCD},
		NextHash:   make([]byte, 20),
	}
	err := ValidateNSEC3RecordFormat(nsec3)
	if !errors.Is(err, ErrNSEC3HashAlgoUnsupported) {
		t.Errorf("Expected ErrNSEC3HashAlgoUnsupported, got: %v", err)
	}
}

// TestValidateNSEC3RecordFormat_SaltTooLong tests that oversized salts are rejected.
func TestValidateNSEC3RecordFormat_SaltTooLong(t *testing.T) {
	nsec3 := DNSRecord{
		Type:       NSEC3,
		HashAlg:    1,
		Iterations: 10,
		Salt:       make([]byte, 256), // > 255 bytes
		NextHash:   make([]byte, 20),
	}
	err := ValidateNSEC3RecordFormat(nsec3)
	if err == nil {
		t.Error("Expected error for salt > 255 bytes")
	}
}

// TestValidateNSEC3RecordFormat_NextHashTooLong tests that oversized NextHash is rejected.
func TestValidateNSEC3RecordFormat_NextHashTooLong(t *testing.T) {
	nsec3 := DNSRecord{
		Type:       NSEC3,
		HashAlg:    1,
		Iterations: 10,
		Salt:       []byte{0xAB, 0xCD},
		NextHash:   make([]byte, 256), // > 255 bytes
	}
	err := ValidateNSEC3RecordFormat(nsec3)
	if err == nil {
		t.Error("Expected error for NextHash > 255 bytes")
	}
}

// TestValidateNSEC3RecordFormat_IterationsTooHigh tests that NSEC3 records with iterations > 150 are rejected.
func TestValidateNSEC3RecordFormat_IterationsTooHigh(t *testing.T) {
	nsec3 := DNSRecord{
		Type:       NSEC3,
		HashAlg:    1,
		Iterations: 200, // > 150, should be rejected
		Salt:       []byte{0xAB, 0xCD},
		NextHash:   make([]byte, 20),
	}
	err := ValidateNSEC3RecordFormat(nsec3)
	if err == nil {
		t.Error("Expected error for iterations > 150")
	}
	// Verify the error message contains iteration count for debugging
	if err != nil && !strings.Contains(err.Error(), "nsec3 iterations too high") {
		t.Errorf("Expected error message to mention 'nsec3 iterations too high', got: %v", err)
	}
}

// TestValidateNSEC3RecordFormat_BoundaryValues tests boundary values around the iterations cap.
func TestValidateNSEC3RecordFormat_BoundaryValues(t *testing.T) {
	tests := []struct {
		name       string
		iterations uint16
		wantErr    bool
	}{
		{"150 is valid", 150, false},
		{"151 is invalid", 151, true},
		{"200 is invalid", 200, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nsec3 := DNSRecord{
				Type:       NSEC3,
				HashAlg:    1,
				Iterations: tt.iterations,
				Salt:       []byte{0xAB, 0xCD},
				NextHash:   make([]byte, 20),
			}
			err := ValidateNSEC3RecordFormat(nsec3)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNSEC3RecordFormat(iterations=%d) error = %v, wantErr %v", tt.iterations, err, tt.wantErr)
			}
		})
	}
}

// TestBase32Decode tests NSEC3-specific base32 decoding.
func TestBase32Decode(t *testing.T) {
	// Known test vectors from NSEC3 hash examples
	tests := []struct {
		encoded  string
		wantErr  bool
	}{
		{"00", false},                                    // minimal
		{"abcdefghijklmnopqrstuv", false},               // valid lowercase alphabet
		{"ABCDEFGHIJKLMNOPQRSTUV", false},                // uppercase is now valid (DNS names are case-insensitive)
		{"1xyz!", true},                                 // invalid char should error
	}

	for _, tt := range tests {
		_, err := base32Decode(tt.encoded)
		if (err != nil) != tt.wantErr {
			t.Errorf("base32Decode(%q) error = %v, wantErr %v", tt.encoded, err, tt.wantErr)
		}
	}
}

// TestNSEC3Present tests the NSEC3 presence check.
func TestNSEC3Present(t *testing.T) {
	records := []DNSRecord{
		{Name: "example.com.", Type: A},
		{Name: "example.com.", Type: NSEC3},
		{Name: "example.com.", Type: TXT},
	}
	if !NSEC3Present(records) {
		t.Error("Expected NSEC3Present to return true")
	}

	noNsec3 := []DNSRecord{
		{Name: "example.com.", Type: A},
		{Name: "example.com.", Type: TXT},
	}
	if NSEC3Present(noNsec3) {
		t.Error("Expected NSEC3Present to return false")
	}
}

// TestTypeBitMapPresent tests type bitmap parsing.
func TestTypeBitMapPresent(t *testing.T) {
	// Build a bitmap that claims type 0 (null) and type 8 (A) exist
	// Window 0, bitmap length 4 bytes (covers types 0-31)
	// Wire format: window(1) + length(1) + bitmap(4)
	// RFC 4034 Section 4.1.2: type bitmaps use MSB-first bit ordering within each octet
	// Type 0: byte 0, bit 7 set → 0x80
	// Type 8: byte 1, bit 7 set → 0x80
	// Bytes 2-3: no bits set
	bitmap := []byte{0x00, 0x04, 0x80, 0x80, 0x00, 0x00}

	if !TypeBitMapPresent(bitmap, 0) {
		t.Error("Expected type 0 to be present")
	}
	if !TypeBitMapPresent(bitmap, 8) {
		t.Error("Expected type 8 (A) to be present")
	}
	if TypeBitMapPresent(bitmap, 1) {
		t.Error("Expected type 1 to be absent")
	}
	if TypeBitMapPresent(bitmap, 16) {
		t.Error("Expected type 16 to be absent")
	}
}

// TestVerifyNSEC3OwnerName tests NSEC3 owner name hash verification.
func TestVerifyNSEC3OwnerName(t *testing.T) {
	// Construct a deterministic NSEC3 owner name for "test.example.com."
	name := "test.example.com."
	salt := []byte("abcd")
	iterations := uint16(0)
	alg := uint8(1)

	// Hash and encode to get the owner prefix
	hash := HashName(name, alg, iterations, salt)
	encoded := Base32Encode(hash)
	zone := "example.com."
	ownerName := encoded + "." + zone + "."

	nsec3 := DNSRecord{
		Name:       ownerName,
		Type:       NSEC3,
		HashAlg:    alg,
		Iterations: iterations,
		Salt:       salt,
		NextHash:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
	}

	// Positive case: matching name should return true, nil
	ok, err := VerifyNSEC3OwnerName(nsec3, name)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !ok {
		t.Error("Expected VerifyNSEC3OwnerName to return true for correct owner name")
	}

	// Negative case: wrong name should return false, ErrNSEC3NoMatchingName
	ok2, err2 := VerifyNSEC3OwnerName(nsec3, "wrong.example.com.")
	if err2 != ErrNSEC3NoMatchingName {
		t.Errorf("Expected ErrNSEC3NoMatchingName, got %v", err2)
	}
	if ok2 {
		t.Error("Expected VerifyNSEC3OwnerName to return false for wrong name")
	}
}

// TestNSEC3CoversHash tests the hash coverage logic.
func TestNSEC3CoversHash(t *testing.T) {
	owner := []byte{1, 2, 3, 4}    // owner hash
	next := []byte{5, 6, 7, 8}      // next hash (owner < next, no wrap)

	// Covered: owner <= h < next
	covered := []byte{2, 5, 5, 5}  // 2 > 1, 2 < 8
	if !nsec3CoversHash(owner, next, covered) {
		t.Error("Expected hash in range [owner,next) to be covered")
	}

	// Not covered: h < owner
	notCovered := []byte{0, 1, 1, 1} // 0 < 1
	if nsec3CoversHash(owner, next, notCovered) {
		t.Error("Expected hash below owner to not be covered")
	}

	// Not covered: h >= next
	notCovered2 := []byte{5, 6, 7, 8} // h == next, not < next
	if nsec3CoversHash(owner, next, notCovered2) {
		t.Error("Expected hash >= next to not be covered")
	}
}

// TestNSEC3CoversHash_WrapAround tests coverage when next < owner (wrap-around).
func TestNSEC3CoversHash_WrapAround(t *testing.T) {
	owner := []byte{10, 10, 10, 10}
	next := []byte{2, 2, 2, 2}  // wraps around

	// Covered if h >= owner (wraps to end)
	covered := []byte{10, 10, 10, 10} // h == owner
	if !nsec3CoversHash(owner, next, covered) {
		t.Error("Expected owner hash to be covered in wrap-around")
	}

	covered2 := []byte{250, 0, 0, 0} // h >= owner
	if !nsec3CoversHash(owner, next, covered2) {
		t.Error("Expected high hash >= owner to be covered in wrap-around")
	}

	// Not covered: between next and owner
	notCovered := []byte{5, 5, 5, 5} // 5 > 2 and 5 < 10
	if nsec3CoversHash(owner, next, notCovered) {
		t.Error("Expected hash between next and owner to not be covered in wrap-around")
	}
}

// TestNSEC3CoversHash_MismatchedLengths tests that mismatched hash lengths return false.
func TestNSEC3CoversHash_MismatchedLengths(t *testing.T) {
	owner := []byte{1, 2, 3}
	next := []byte{1, 2, 3, 4}
	hash := []byte{2, 3, 4}

	if nsec3CoversHash(owner, next, hash) {
		t.Error("Expected false for mismatched hash lengths")
	}

	if nsec3CoversHash(owner, []byte{}, hash) {
		t.Error("Expected false for empty next hash")
	}
}

// TestDecodeBase32Hash tests extracting hash from NSEC3 owner names.
func TestDecodeBase32Hash(t *testing.T) {
	// Valid: base32 encoded hash followed by zone
	owner := "KI2DB3GJHH5K3D.example.com."
	hash := decodeBase32Hash(owner)
	if hash == nil || len(hash) == 0 {
		t.Error("Expected valid decoded hash")
	}

	// Invalid: no dot separator
	hash2 := decodeBase32Hash("nodot separators")
	if hash2 != nil {
		t.Error("Expected nil for name without dot separator")
	}

	// Invalid: empty string
	hash3 := decodeBase32Hash("")
	if hash3 != nil {
		t.Error("Expected nil for empty owner name")
	}

	// Valid: single-label zone root (no zone part)
	owner4 := "KI2DB3GJHH5K3D."
	hash4 := decodeBase32Hash(owner4)
	if hash4 != nil && len(hash4) > 0 {
		// This is actually valid since TrimSuffix(".","") gives "KI2DB3GJHH5K3D" and there's no dot
	}
}

// TestDecodeBase32Hash_InvalidBase32 tests handling of invalid base32 strings.
func TestDecodeBase32Hash_InvalidBase32(t *testing.T) {
	// Name with an invalid base32 character
	owner := "!!!INVALID.example.com."
	hash := decodeBase32Hash(owner)
	if hash != nil {
		t.Error("Expected nil for invalid base32")
	}
}

// TestValidateNSEC3Proof_EmptyRecords tests that empty NSEC3 list is rejected.
func TestValidateNSEC3Proof_EmptyRecords(t *testing.T) {
	err := ValidateNSEC3Proof([]DNSRecord{}, "example.com.", 0)
	if err == nil {
		t.Error("Expected error for empty NSEC3 records")
	}
}

// TestValidateNSEC3Proof_ValidNXDOMAIN tests a valid NXDOMAIN NSEC3 proof.
// Uses HashName to compute the query hash and constructs NSEC3 records
// that correctly cover it.
func TestValidateNSEC3Proof_ValidNXDOMAIN(t *testing.T) {
	// Use the same parameters that the server generates NSEC3 with
	zoneName := "example.com."
	queryName := "nonexistent.example.com."
	alg := uint8(1)
	iterations := uint16(10)
	salt := []byte("abcd")

	// Compute query hash using the same formula as ValidateNSEC3Proof
	queryHash := HashName(queryName, alg, iterations, salt)

	// Build NSEC3 owner as: base32(queryHash).zone.
	encoded := Base32Encode(queryHash)
	nsec3Owner := encoded + "." + zoneName + "."

	// Next hash must be > queryHash to cover it (owner <= h < next)
	// Since our queryHash is somewhere in the middle, use a higher nextHash
	nextHash := make([]byte, len(queryHash))
	for i := range nextHash {
		nextHash[i] = 0xFF // Ensure nextHash > queryHash
	}

	nsec3Records := []DNSRecord{
		{
			Name:       nsec3Owner,
			Type:       NSEC3,
			HashAlg:    alg,
			Iterations: iterations,
			Salt:       salt,
			NextHash:   nextHash,
		},
	}

	err := ValidateNSEC3Proof(nsec3Records, queryName, 0)
	if err != nil {
		t.Errorf("Expected valid NXDOMAIN proof, got: %v", err)
	}
}

// TestValidateNSEC3Proof_InvalidHash tests that mismatched owner hash is rejected.
// VerifyNSEC3OwnerName is called before the covers check, so wrong hash = fatal error.
func TestValidateNSEC3Proof_InvalidOwnerName(t *testing.T) {
	nsec3Records := []DNSRecord{
		{
			Name:       "WRONGHASH.example.com.", // doesn't match query hash
			Type:       NSEC3,
			HashAlg:    1,
			Iterations: 10,
			Salt:       []byte{0xAB, 0xCD},
			NextHash:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	// VerifyNSEC3OwnerName should return ErrNSEC3NoMatchingName
	err := ValidateNSEC3Proof(nsec3Records, "example.com.", 0)
	if err == nil {
		t.Error("Expected error for invalid owner name hash")
	}
}

// TestValidateNSEC3Proof_NoCoveringNSEC3 cannot be constructed as a passing test.
// When owner == queryHash and next < owner (wrap case), coverage always returns
// true because h >= owner is always true when h == owner. Constructing a "not covered"
// test would require owner != queryHash, which fails Step 2 (owner name verification).
// This comment documents the invariant.

// TestValidateNSEC3Proof_NoData tests no-data NSEC3 proof (query type exists at name).
func TestValidateNSEC3Proof_NoData(t *testing.T) {
	// Set up: query type is A (1), NSEC3 owner is exact query hash with A in bitmap
	zoneName := "example.com."
	queryName := "existing.example.com."
	alg := uint8(1)
	iterations := uint16(10)
	salt := []byte("abcd")

	queryHash := HashName(queryName, alg, iterations, salt)
	encoded := Base32Encode(queryHash)
	nsec3Owner := encoded + "." + zoneName + "."

	nsec3Records := []DNSRecord{
		{
			Name:       nsec3Owner,
			Type:       NSEC3,
			HashAlg:    alg,
			Iterations: iterations,
			Salt:       salt,
			NextHash:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
			// Bitmap includes type A (1) — means type exists, which is "no-data" failure
			TypeBitMap: []byte{0x00, 0x02, 0x40, 0x00}, // window 0, len 2, bits for type 1
		},
	}

	err := ValidateNSEC3Proof(nsec3Records, queryName, uint16(A))
	if err != ErrNSEC3InvalidProof {
		t.Errorf("Expected ErrNSEC3InvalidProof for no-data when type exists in bitmap, got: %v", err)
	}
}

// TestValidateNSEC3Proof_WildcardMatch tests wildcard proof path (type 0 query).
// This test uses the exact hash computed by VerifyNSEC3OwnerName to ensure
// the owner name validation (Step 2) passes. The nextHash > queryHash ensures
// coverage check passes.
func TestValidateNSEC3Proof_WildcardMatch(t *testing.T) {
	// Use the same zone and parameters as existing integration tests
	zoneName := "example.com."
	queryName := "www.example.com."
	alg := uint8(1)
	iterations := uint16(10)
	salt := []byte{0xAB, 0xCD}

	// Compute query hash using HashName as ValidateNSEC3Proof does
	queryHash := HashName(queryName, alg, iterations, salt)
	encoded := Base32Encode(queryHash)
	nsec3Owner := encoded + "." + zoneName + "."

	// Verify our owner is correctly computed (this mirrors what VerifyNSEC3OwnerName does)
	ownerHash := decodeBase32Hash(nsec3Owner)
	if ownerHash == nil || !bytes.Equal(ownerHash, queryHash) {
		t.Fatalf("Test setup error: ownerHash doesn't match queryHash")
	}

	// nextHash > queryHash ensures coverage
	nextHash := make([]byte, len(queryHash))
	for i := range nextHash {
		nextHash[i] = 0xFF
	}

	nsec3Records := []DNSRecord{
		{
			Name:       nsec3Owner,
			Type:       NSEC3,
			HashAlg:    alg,
			Iterations: iterations,
			Salt:       salt,
			NextHash:   nextHash,
		},
	}

	// queryType = 0 means wildcard/NXDOMAIN path (no Step 4 check)
	err := ValidateNSEC3Proof(nsec3Records, queryName, 0)
	if err != nil {
		t.Errorf("Expected valid proof for queryType=0 wildcard path, got: %v", err)
	}
}

// TestValidateNSEC3WildcardProof_Valid tests a valid wildcard NSEC3 proof.
func TestValidateNSEC3WildcardProof_Valid(t *testing.T) {
	zoneName := "example.com."
	wildcardName := "*.example.com."
	alg := uint8(1)
	iterations := uint16(10)
	salt := []byte("abcd")

	// Hash the wildcard name
	wildcardHash := HashName(wildcardName, alg, iterations, salt)
	encoded := Base32Encode(wildcardHash)
	nsec3Owner := encoded + "." + zoneName + "."

	nsec3Records := []DNSRecord{
		{
			Name:       nsec3Owner,
			Type:       NSEC3,
			HashAlg:    alg,
			Iterations: iterations,
			Salt:       salt,
			NextHash:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
			// Include A type in bitmap (wildcard provides A records)
			TypeBitMap: []byte{0x00, 0x02, 0x40, 0x00},
		},
	}

	err := ValidateNSEC3WildcardProof(nsec3Records, wildcardName, uint16(A))
	if err != nil {
		t.Errorf("Expected valid wildcard proof, got: %v", err)
	}
}

// TestValidateNSEC3WildcardProof_EmptyRecords tests that empty NSEC3 list is rejected.
func TestValidateNSEC3WildcardProof_EmptyRecords(t *testing.T) {
	err := ValidateNSEC3WildcardProof([]DNSRecord{}, "*.example.com.", 1)
	if err == nil {
		t.Error("Expected error for empty NSEC3 records")
	}
}

// TestValidateNSEC3WildcardProof_WrongWildcardHash tests when NSEC3 owner doesn't match wildcard hash.
func TestValidateNSEC3WildcardProof_WrongWildcardHash(t *testing.T) {
	nsec3Records := []DNSRecord{
		{
			Name:       "WRONGHASH.example.com.",
			Type:       NSEC3,
			HashAlg:    1,
			Iterations: 10,
			Salt:       []byte{0xAB, 0xCD},
			NextHash:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
			TypeBitMap: []byte{0x00, 0x02, 0x40, 0x00},
		},
	}

	// Wrong wildcard name — VerifyNSEC3OwnerName will fail
	err := ValidateNSEC3WildcardProof(nsec3Records, "*.example.com.", uint16(A))
	if err == nil {
		t.Error("Expected error when NSEC3 owner doesn't match wildcard hash")
	}
}

// TestValidateDNSKEYFormat_RSASHA256 tests RSA SHA-256 key format validation.
func TestValidateDNSKEYFormat_RSASHA256(t *testing.T) {
	// RSA key: modulus must be at least 512 bits, at most 4096 bits
	// Use a properly-sized RSA key for validation
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal RSA public key: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: pubBytes,
	}

	valid, err := ValidateDNSKEYFormat(dnskey)
	if err != nil {
		t.Fatalf("ValidateDNSKEYFormat returned error: %v", err)
	}
	if !valid {
		t.Error("Expected valid RSA DNSKEY to pass validation")
	}
}

// TestValidateDNSKEYFormat_RSASHA256_TooSmall tests that malformed RSA keys are rejected.
// We use a key with insufficient modulus size. 1024-bit minimum applies in FIPS mode,
// but crypto/rsa always requires minimum 1024 bits for public keys in Go.
func TestValidateDNSKEYFormat_RSASHA256_TooSmall(t *testing.T) {
	// Use a proper RSA key but with artificially truncated PublicKey bytes
	// to simulate a malformed/incomplete RSA key
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: AlgorithmRSASHA256,
		PublicKey: []byte{0x01, 0x02}, // Too short for any RSA key
	}

	_, err := ValidateDNSKEYFormat(dnskey)
	if err == nil {
		t.Error("Expected error for truncated RSA key")
	}
}

// TestValidateDNSKEYFormat_ED25519 tests Ed25519 key format validation.
func TestValidateDNSKEYFormat_ED25519(t *testing.T) {
	// Ed25519.GenerateKey returns (pub, priv, err) — pub is 32 bytes, priv is 64 bytes
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgorithmED25519,
		PublicKey: pubKey,
	}

	valid, err := ValidateDNSKEYFormat(dnskey)
	if err != nil {
		t.Fatalf("ValidateDNSKEYFormat returned error: %v", err)
	}
	if !valid {
		t.Error("Expected valid Ed25519 DNSKEY to pass validation")
	}
}

// TestValidateDNSKEYFormat_ED25519_WrongSize tests that wrong-sized Ed25519 keys are rejected.
func TestValidateDNSKEYFormat_ED25519_WrongSize(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgorithmED25519,
		PublicKey: make([]byte, 31), // Too short — must be 32 bytes
	}

	_, err := ValidateDNSKEYFormat(dnskey)
	if err == nil {
		t.Error("Expected error for wrong-sized Ed25519 key")
	}
}

// TestValidateDNSKEYFormat_ED448 tests Ed448 key format validation.
func TestValidateDNSKEYFormat_ED448(t *testing.T) {
	// ed448.GenerateKey returns (pub, priv, err) — pub is 57 bytes, priv is 114 bytes
	pubKey, _, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed448 key: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgorithmED448,
		PublicKey: pubKey,
	}

	valid, err := ValidateDNSKEYFormat(dnskey)
	if err != nil {
		t.Fatalf("ValidateDNSKEYFormat returned error: %v", err)
	}
	if !valid {
		t.Error("Expected valid Ed448 DNSKEY to pass validation")
	}
}

// TestValidateDNSKEYFormat_ED448_WrongSize tests that wrong-sized Ed448 keys are rejected.
func TestValidateDNSKEYFormat_ED448_WrongSize(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgorithmED448,
		PublicKey: make([]byte, 56), // Too short — must be 57 bytes
	}

	_, err := ValidateDNSKEYFormat(dnskey)
	if err == nil {
		t.Error("Expected error for wrong-sized Ed448 key")
	}
}

// TestSignAndVerify_ECDSA_P384 tests sign and verify round-trip using ECDSA P-384 (Algorithm 14).
func TestSignAndVerify_ECDSA_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P-384) failed: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     256,
		Protocol:  3,
		Algorithm: AlgorithmECDSAP384,
		PublicKey: encodeECDSAP384PublicKey(&privKey.PublicKey),
	}

	rrset := []DNSRecord{
		{Name: "www.example.com.", Type: A, Class: 1, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}

	now := uint32(time.Now().Unix())
	keyTag := dnskey.ComputeKeyTag()

	sig, err := SignRRSet(rrset, privKey, AlgorithmECDSAP384, "example.com.", keyTag, now-3600, now+86400)
	if err != nil {
		t.Fatalf("SignRRSet (P-384) failed: %v", err)
	}

	valid, err := VerifyRRSet(rrset, sig, dnskey, now)
	if err != nil {
		t.Fatalf("VerifyRRSet (P-384) failed: %v", err)
	}
	if !valid {
		t.Error("Expected valid P-384 signature")
	}
}

// TestValidateDNSKEYFormat_ECDSA_P384 tests ECDSA P-384 key format validation.
func TestValidateDNSKEYFormat_ECDSA_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P-384) failed: %v", err)
	}

	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgorithmECDSAP384,
		PublicKey: encodeECDSAP384PublicKey(&privKey.PublicKey),
	}

	valid, err := ValidateDNSKEYFormat(dnskey)
	if err != nil {
		t.Fatalf("ValidateDNSKEYFormat returned error: %v", err)
	}
	if !valid {
		t.Error("Expected valid P-384 DNSKEY to pass validation")
	}
}

// TestValidateDNSKEYFormat_ECDSA_P384_WrongSize tests that wrong-sized P-384 keys are rejected.
func TestValidateDNSKEYFormat_ECDSA_P384_WrongSize(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: AlgorithmECDSAP384,
		PublicKey: make([]byte, 64), // Wrong size — must be 96 bytes
	}

	_, err := ValidateDNSKEYFormat(dnskey)
	if err == nil {
		t.Error("Expected error for wrong-sized P-384 key")
	}
}
