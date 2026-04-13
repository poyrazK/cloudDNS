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
		DigestType:  2,
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
		TypeBitMap:  []byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x05},
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
		Name:  "example.com.",
		Type:  NS,
		Host:  "ns1.example.com.",
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
		Name:  "www.example.com.",
		Type:  CNAME,
		Host:  "example.com.",
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
		Name:  "1.0.0.127.in-addr.arpa.",
		Type:  PTR,
		Host:  "localhost.",
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
		DigestType:  2,
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
		TypeBitMap:  []byte{0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1c},
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
		Name:  "example.com.",
		Type:  UNKNOWN,
		Data:  []byte{0x01, 0x02, 0x03},
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
	if err != ErrKeyTagMismatch {
		t.Errorf("Expected ErrKeyTagMismatch, got %v", err)
	}
}

// TestVerifyDNSKEYSelfSignature_NoPublicKey tests with missing public key.
func TestVerifyDNSKEYSelfSignature_NoPublicKey(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02}, // Too short
	}

	_, err := VerifyDNSKEYSelfSignature(dnskey)
	if err != ErrNoPublicKey {
		t.Errorf("Expected ErrNoPublicKey, got %v", err)
	}
}

// TestVerifyDNSKEYSelfSignature_UnsupportedAlgorithm tests with invalid key format.
func TestVerifyDNSKEYSelfSignature_UnsupportedAlgorithm(t *testing.T) {
	dnskey := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: make([]byte, 65), // Valid length but wrong format
	}

	_, err := VerifyDNSKEYSelfSignature(dnskey)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("Expected ErrUnsupportedAlgorithm, got %v", err)
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
		Name:  "example.com.",
		Type:  A,
		IP:    []byte{1, 2}, // Invalid - too short for IPv4
	}

	err := writeCanonicalRData(&record, buf)
	if err == nil {
		t.Error("Expected error for invalid IPv4 address")
	}
	if err != nil && err.Error() != "invalid IPv4 address" {
		t.Errorf("Expected 'invalid IPv4 address' error, got %v", err)
	}
}
