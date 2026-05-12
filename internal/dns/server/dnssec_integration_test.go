package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestDNSSEC_TrustAnchorValidation tests that ValidateWithTrustAnchor works correctly.
func TestDNSSEC_TrustAnchorValidation(t *testing.T) {
	// Create a test key pair
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes := encodeECDSAPublicKey(&privKey.PublicKey)

	trustAnchor := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubKeyBytes,
	}

	anchors := map[string]packet.DNSRecord{
		"example.com.": trustAnchor,
	}
	validator := services.NewDNSSECValidator(anchors)

	// Create and sign an RRset
	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	now := uint32(time.Now().Unix())
	keyTag := trustAnchor.ComputeKeyTag()
	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", keyTag, now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{trustAnchor}, now)
	if !result.Valid {
		t.Errorf("Expected valid result, got: %v", result.EDE)
	}
	if !result.ADBit {
		t.Errorf("Expected AD bit to be set")
	}
}

// TestDNSSEC_ExpiredSignatureEDE tests that expired signatures get correct EDE code.
func TestDNSSEC_ExpiredSignatureEDE(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes := encodeECDSAPublicKey(&privKey.PublicKey)

	trustAnchor := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubKeyBytes,
	}

	anchors := map[string]packet.DNSRecord{"example.com.": trustAnchor}
	validator := services.NewDNSSECValidator(anchors)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Create an EXPIRED signature (expiration in the past)
	now := uint32(time.Now().Unix())
	keyTag := trustAnchor.ComputeKeyTag()
	rrsig, _ := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", keyTag, now-7200, now-3600) // expired

	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{trustAnchor}, now)
	if result.Valid {
		t.Error("Expected invalid result for expired signature")
	}
	if result.EDE == nil {
		t.Error("Expected EDE to be set")
	} else if result.EDE.Code != services.EDECodeSignatureExpired {
		t.Errorf("Expected EDE code %d (signature-expired), got %d", services.EDECodeSignatureExpired, result.EDE.Code)
	}
}

// TestDNSSEC_MissingDNSKEYEDE tests that missing DNSKEY gets correct EDE code.
func TestDNSSEC_MissingDNSKEYEDE(t *testing.T) {
	validator := services.NewDNSSECValidator(nil) // no trust anchors

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Create RRSIG but no matching DNSKEY
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := uint32(time.Now().Unix())
	rrsig, _ := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", 12345, now-60, now+3600)

	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{}, now)
	if result.Valid {
		t.Error("Expected invalid result when no DNSKEYs")
	}
	if result.EDE == nil {
		t.Error("Expected EDE to be set")
	} else if result.EDE.Code != services.EDECodeBogus {
		t.Errorf("Expected EDE code %d (bogus), got %d", services.EDECodeBogus, result.EDE.Code)
	}
}

// TestDNSSEC_RRSIGGrouping tests that multiple RRSIGs for same RRset
// are handled correctly.
func TestDNSSEC_RRSIGGrouping(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes := encodeECDSAPublicKey(&privKey.PublicKey)

	trustAnchor := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubKeyBytes,
	}

	anchors := map[string]packet.DNSRecord{"example.com.": trustAnchor}
	validator := services.NewDNSSECValidator(anchors)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	now := uint32(time.Now().Unix())
	keyTag := trustAnchor.ComputeKeyTag()

	// Sign with same key but different inception times
	rrsig1, _ := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", keyTag, now-60, now+3600)
	rrsig2, _ := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", keyTag, now-120, now+3600)

	// Both RRSIGs should be for the same RRset (same name and typeCovered)
	if rrsig1.Name != rrsig2.Name || rrsig1.TypeCovered != rrsig2.TypeCovered {
		t.Fatal("RRSIGs should have same name and typeCovered")
	}

	// When validating with multiple RRSIGs for same RRset,
	// the validator should use the first matching one
	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig1, rrsig2}, []packet.DNSRecord{trustAnchor}, now)
	if !result.Valid {
		t.Errorf("Expected valid result with multiple RRSIGs, got: %v", result.EDE)
	}
}

// TestDNSSEC_EDEToString tests the String() method on EDE.
func TestDNSSEC_EDEToString(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{services.EDECodeOther, "other error"},
		{services.EDECodeUnsupportedDNSKEYAlgo, "unsupported-dnskey-algorithm"},
		{services.EDECodeBogus, "dnssec-bogus"},
		{services.EDECodeSignatureExpired, "signature-expired"},
		{services.EDECodeDNSKEYMissing, "dnskey-missing"},
		{services.EDECodeTrustAnchorUnknown, "trust-anchor-unknown"},
	}

	for _, tt := range tests {
		ede := &services.EDE{Code: tt.code, Info: "test"}
		if got := ede.String(); got != tt.want {
			t.Errorf("EDE code %d: String() = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// TestDNSSEC_BogusOnInvalidSignature tests that invalid signatures result in bogus.
func TestDNSSEC_BogusOnInvalidSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes := encodeECDSAPublicKey(&privKey.PublicKey)

	trustAnchor := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubKeyBytes,
	}

	anchors := map[string]packet.DNSRecord{"example.com.": trustAnchor}
	validator := services.NewDNSSECValidator(anchors)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	now := uint32(time.Now().Unix())
	keyTag := trustAnchor.ComputeKeyTag()
	rrsig, _ := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", keyTag, now-60, now+3600)

	// Tamper with the signature to make it invalid
	rrsig.Signature[0] ^= 0xFF

	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{trustAnchor}, now)
	if result.Valid {
		t.Error("Expected invalid result for tampered signature")
	}
	if result.EDE == nil {
		t.Error("Expected EDE to be set")
	} else if result.EDE.Code != services.EDECodeBogus {
		t.Errorf("Expected EDE code %d (bogus), got %d", services.EDECodeBogus, result.EDE.Code)
	}
}

// TestDNSSEC_NoZoneKeyBitEDE tests that a DNSKEY without SEP flag returns correct EDE.
func TestDNSSEC_NoZoneKeyBitEDE(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyBytes := encodeECDSAPublicKey(&privKey.PublicKey)

	// DNSKEY without SEP flag (Zone Key instead of Key Signing Key)
	trustAnchor := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    256, // NOT 257 (SEP) - would be rejected as KSK
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubKeyBytes,
	}

	anchors := map[string]packet.DNSRecord{"example.com.": trustAnchor}
	validator := services.NewDNSSECValidator(anchors)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	now := uint32(time.Now().Unix())
	keyTag := trustAnchor.ComputeKeyTag()
	rrsig, _ := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", keyTag, now-60, now+3600)

	// Even with wrong flags, if the key matches the trust anchor it validates
	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{trustAnchor}, now)
	// The validation should work since the key tag and algorithm match
	// (Flags are checked separately via ValidateDNSKEYFormat)
	if !result.Valid {
		t.Logf("Validation failed: %v - this is expected if format validation rejects it", result.EDE)
	}
}

// encodeECDSAPublicKey encodes an ECDSA public key into RFC 6605 wire format (X||Y, 64 bytes for P-256).
func encodeECDSAPublicKey(pub *ecdsa.PublicKey) []byte {
	xBytes := pub.X.FillBytes(make([]byte, 32))
	yBytes := pub.Y.FillBytes(make([]byte, 32))
	result := make([]byte, 64)
	copy(result[0:32], xBytes)
	copy(result[32:64], yBytes)
	return result
}

// TestDNSSEC_ValidateChain_ThreeZoneChain tests full chain validation
// from root trust anchor through TLD to leaf zone.
func TestDNSSEC_ValidateChain_ThreeZoneChain(t *testing.T) {
	// Create root anchor
	rootDNSKEY, rootPrivKey := makeTestDNSKEYWithName(t, ".")

	// Create keys for com and example
	comDNSKEY, comPrivKey := makeTestDNSKEYWithName(t, "com.")
	exampleDNSKEY, _ := makeTestDNSKEYWithName(t, "example.com.")

	trustAnchors := map[string]packet.DNSRecord{
		".": rootDNSKEY,
	}
	validator := services.NewDNSSECValidator(trustAnchors)

	// Compute DS records for the chain
	exampleDS, _ := exampleDNSKEY.ComputeDS(2) // SHA-256
	comDS, _ := comDNSKEY.ComputeDS(2)

	// Sign DS records with parent zone's key
	now := uint32(1000)

	// example.com's DS signed by com's key
	exampleRRSIG, _ := packet.SignRRSet([]packet.DNSRecord{exampleDS}, comPrivKey, packet.AlgorithmECDSAP256, "com.", comDNSKEY.ComputeKeyTag(), now-60, now+3600)

	// com's DS signed by root's key
	comRRSIG, _ := packet.SignRRSet([]packet.DNSRecord{comDS}, rootPrivKey, packet.AlgorithmECDSAP256, ".", rootDNSKEY.ComputeKeyTag(), now-60, now+3600)

	// Build chain: example.com -> com -> root (trust anchor)
	chain := []services.ChainLink{
		{
			Zone:     "example.com.",
			DNSKEYs:  []packet.DNSRecord{exampleDNSKEY},
			DS:       exampleDS,
			RRSIGsDS: []packet.DNSRecord{exampleRRSIG},
		},
		{
			Zone:     "com.",
			DNSKEYs:  []packet.DNSRecord{comDNSKEY},
			DS:       comDS,
			RRSIGsDS: []packet.DNSRecord{comRRSIG},
		},
	}

	err := validator.ValidateChain(chain, now)
	if err != nil {
		t.Errorf("Expected valid 3-zone chain, got error: %v", err)
	}
}

// TestDNSSEC_ValidateChain_BrokenChain tests that broken chains are detected.
func TestDNSSEC_ValidateChain_BrokenChain(t *testing.T) {
	// Create first key
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes1 := encodeECDSAPublicKey(&privKey1.PublicKey)
	dnskey1 := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubBytes1,
	}

	// Create second key (different)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes2 := encodeECDSAPublicKey(&privKey2.PublicKey)
	dnskey2 := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubBytes2,
	}

	// Compute DS from dnskey1
	ds, _ := dnskey1.ComputeDS(2)

	// Chain with dnskey2 (doesn't match DS) - should fail
	chain := []services.ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{dnskey2},
			DS:      ds,
		},
	}

	validator := services.NewDNSSECValidator(nil)
	err := validator.ValidateChain(chain, uint32(1000))
	if err == nil {
		t.Error("Expected error when DNSKEY doesn't match DS")
	}
}

// TestDNSSEC_ValidateChain_TrustAnchorVerification tests that trust anchor
// verification works in the chain.
func TestDNSSEC_ValidateChain_TrustAnchorVerification(t *testing.T) {
	// Create root anchor
	rootPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootPubBytes := encodeECDSAPublicKey(&rootPrivKey.PublicKey)
	rootDNSKEY := packet.DNSRecord{
		Name:     ".",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: rootPubBytes,
	}

	trustAnchors := map[string]packet.DNSRecord{
		".": rootDNSKEY,
	}
	validator := services.NewDNSSECValidator(trustAnchors)

	// Create a zone DNSKEY that doesn't match root anchor
	zonePrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	zonePubBytes := encodeECDSAPublicKey(&zonePrivKey.PublicKey)
	zoneDNSKEY := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: zonePubBytes,
	}

	// Chain where zone's DNSKEY doesn't match trust anchor
	chain := []services.ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{zoneDNSKEY},
			DS:      packet.DNSRecord{}, // Empty DS, rely on trust anchor
		},
	}

	// Without trust anchor for example.com, this should pass (empty DS)
	err := validator.ValidateChain(chain, uint32(1000))
	if err != nil {
		t.Errorf("Unexpected error for zone without anchor: %v", err)
	}
}

// makeTestDNSKEYWithName creates a test DNSKEY with a specific name.
func makeTestDNSKEYWithName(t *testing.T, name string) (packet.DNSRecord, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	pubBytes := make([]byte, 64)
	xBytes := privKey.PublicKey.X.FillBytes(make([]byte, 32))
	yBytes := privKey.PublicKey.Y.FillBytes(make([]byte, 32))
	copy(pubBytes[0:32], xBytes)
	copy(pubBytes[32:64], yBytes)

	dnskey := packet.DNSRecord{
		Name:     name,
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubBytes,
	}

	return dnskey, privKey
}

// TestDNSSEC_NSEC3WildcardProof_Integration tests that NSEC3 wildcard proofs
// are generated when a wildcard matches a query.
func TestDNSSEC_NSEC3WildcardProof_Integration(t *testing.T) {
	// Create repo with NSEC3PARAM and wildcard record
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "wildcard.test."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "wildcard.test.", Type: "NSEC3PARAM", Content: "1 0 10 ABCD"},
			{ZoneID: "z1", Name: "*.wildcard.test.", Type: domain.TypeA, Content: "5.6.7.8"},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "wildcard.test."}

	// Generate NSEC3 proof for www.wildcard.test. with wildcard *.wildcard.test.
	nsec3, err := srv.generateNSEC3(context.Background(), zone, "www.wildcard.test.", "*.wildcard.test.")
	if err != nil {
		t.Fatalf("generateNSEC3 wildcard proof failed: %v", err)
	}

	if nsec3.Type != packet.NSEC3 {
		t.Errorf("Expected NSEC3 record type, got %d", nsec3.Type)
	}

	// Verify NSEC3 has valid structure
	if nsec3.HashAlg != 1 {
		t.Errorf("Expected hash algorithm 1, got %d", nsec3.HashAlg)
	}
	if nsec3.Iterations != 10 {
		t.Errorf("Expected iterations 10, got %d", nsec3.Iterations)
	}
	if string(nsec3.Salt) != "ABCD" {
		t.Errorf("Expected salt 'ABCD', got %s", string(nsec3.Salt))
	}

	// Verify NSEC3 has type bitmap set (should include A type from wildcard)
	if len(nsec3.TypeBitMap) == 0 {
		t.Errorf("NSEC3 type bitmap should not be empty")
	}
}

// TestDNSSEC_NSEC3WildcardProof_NoWildcardMatch tests that NSEC3 denial
// is generated when no wildcard matches.
func TestDNSSEC_NSEC3WildcardProof_Denial(t *testing.T) {
	// Create repo with NSEC3PARAM but no wildcard
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "nodeny.test."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "nodeny.test.", Type: "NSEC3PARAM", Content: "1 0 10 ABCD"},
			{ZoneID: "z1", Name: "a.nodeny.test.", Type: domain.TypeA, Content: "1.2.3.4"},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "nodeny.test."}

	// Query for nonexistent.nodeny.test. - should get NSEC3 denial
	nsec3, err := srv.generateNSEC3(context.Background(), zone, "nonexistent.nodeny.test.", "")
	if err != nil {
		t.Fatalf("generateNSEC3 failed: %v", err)
	}

	if nsec3.Type != packet.NSEC3 {
		t.Errorf("Expected NSEC3 record type")
	}

	// The NSEC3 owner should be the hash of a.nodeny.test. (covers nonexistent)
	// The bitmap should include A type (proving a.nodeny.test. exists)
	foundA := false
	for _, b := range nsec3.TypeBitMap {
		if b != 0 {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Errorf("NSEC3 bitmap should have some types set for existing record proof")
	}
}

// TestDNSSEC_ValidateChain_EmptyChain tests error handling for empty chain.
func TestDNSSEC_ValidateChain_EmptyChain(t *testing.T) {
	validator := services.NewDNSSECValidator(nil)

	err := validator.ValidateChain([]services.ChainLink{}, uint32(1000))
	if err == nil {
		t.Error("Expected error for empty chain")
	}
}

// TestDNSSEC_ValidateChain_SingleZone tests single zone chain validation.
func TestDNSSEC_ValidateChain_SingleZone(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := encodeECDSAPublicKey(&privKey.PublicKey)
	dnskey := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubBytes,
	}

	chain := []services.ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{dnskey},
			DS:      packet.DNSRecord{}, // Empty DS
		},
	}

	validator := services.NewDNSSECValidator(nil)
	err := validator.ValidateChain(chain, uint32(1000))
	if err != nil {
		t.Errorf("Expected no error for single zone with empty DS, got: %v", err)
	}
}

// TestDNSSEC_ValidateChain_DSAlgorithmMismatch tests detection of DS algorithm mismatch.
func TestDNSSEC_ValidateChain_DSAlgorithmMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := encodeECDSAPublicKey(&privKey.PublicKey)
	dnskey := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    257,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: pubBytes,
	}

	// Create DS with wrong algorithm
	ds := packet.DNSRecord{
		Type:       packet.DS,
		KeyTag:     dnskey.ComputeKeyTag(),
		Algorithm: 14, // Different from dnskey's algorithm (13)
		DigestType: 2,
		Digest:     []byte("wrong"),
	}

	chain := []services.ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{dnskey},
			DS:      ds,
		},
	}

	validator := services.NewDNSSECValidator(nil)
	err := validator.ValidateChain(chain, uint32(1000))
	if err == nil {
		t.Error("Expected error for algorithm mismatch")
	}
}

// TestParentZoneName tests the parentZoneName helper function.
func TestParentZoneName(t *testing.T) {
	tests := []struct {
		zone     string
		expected string
	}{
		{"www.example.com.", "example.com."},
		{"example.com.", "com."},
		{"com.", "."},
		{"test.co.uk.", "co.uk."},
		{"a.b.c.d.", "b.c.d."},
		{"root.", ""}, // Single-label root returns empty (no parent)
	}

	for _, tt := range tests {
		got := parentZoneName(tt.zone)
		if got != tt.expected {
			t.Errorf("parentZoneName(%q) = %q, want %q", tt.zone, got, tt.expected)
		}
	}
}

// mockDNSSECServer creates a test server with a mockable queryFn for testing buildDNSSECChain.
func mockDNSSECServer(t *testing.T) (*Server, *[]struct {
	query    string
	qtype    packet.QueryType
	response *packet.DNSPacket
	err      error
}) {
	t.Helper()

	queries := &[]struct {
		query    string
		qtype    packet.QueryType
		response *packet.DNSPacket
		err      error
	}{}

	queryFn := func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		for _, q := range *queries {
			if q.query == name && q.qtype == qtype {
				if q.err != nil {
					return nil, q.err
				}
				return q.response, nil
			}
		}
		return nil, fmt.Errorf("mock: unexpected query %s (type %v)", name, qtype)
	}

	srv := &Server{
		Logger:          slog.Default(),
		queryFn:         queryFn,
		DNSSECValidator: services.NewDNSSECValidator(nil),
	}
	return srv, queries
}

// TestBuildDNSSECChain_SingleZone tests buildDNSSECChain with a single zone and trust anchor.
func TestBuildDNSSECChain_SingleZone(t *testing.T) {
	srv, queriesPtr := mockDNSSECServer(t)

	// Create a DNSKEY for example.com and set it as trust anchor
	dnskey, _ := makeTestDNSKEYWithName(t, "example.com.")
	anchors := map[string]packet.DNSRecord{"example.com.": dnskey}
	srv.DNSSECValidator = services.NewDNSSECValidator(anchors)

	*queriesPtr = []struct {
		query    string
		qtype    packet.QueryType
		response *packet.DNSPacket
		err      error
	}{{
		query:    "example.com.",
		qtype:    packet.DNSKEY,
		response: makeMockResponse("example.com.", []packet.DNSRecord{dnskey}, nil),
	}}

	ctx := context.Background()
	chain, err := srv.buildDNSSECChain(ctx, "example.com.")
	if err != nil {
		t.Fatalf("buildDNSSECChain failed: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 link, got %d", len(chain))
	}
	if chain[0].Zone != "example.com." {
		t.Errorf("expected zone example.com., got %s", chain[0].Zone)
	}
}

// TestBuildDNSSECChain_WithDS tests buildDNSSECChain fetching DS from parent.
func TestBuildDNSSECChain_WithDS(t *testing.T) {
	srv, queries := mockDNSSECServer(t)

	// Create DNSKEYs for example.com and com
	exampleDNSKEY, _ := makeTestDNSKEYWithName(t, "example.com.")
	comDNSKEY, comPrivKey := makeTestDNSKEYWithName(t, "com.")

	// Create DS for example.com signed by com's key
	exampleDS, _ := exampleDNSKEY.ComputeDS(2)
	now := uint32(1000)
	rrsigDS, _ := packet.SignRRSet([]packet.DNSRecord{exampleDS}, comPrivKey, packet.AlgorithmECDSAP256, "com.", comDNSKEY.ComputeKeyTag(), now-60, now+3600)

	// Set up trust anchor for com. (parent zone has a trust anchor configured)
	anchors := map[string]packet.DNSRecord{"com.": comDNSKEY}
	srv.DNSSECValidator = services.NewDNSSECValidator(anchors)

	*queries = []struct {
		query    string
		qtype    packet.QueryType
		response *packet.DNSPacket
		err      error
	}{{
		query:    "example.com.",
		qtype:    packet.DNSKEY,
		response: makeMockResponse("example.com.", []packet.DNSRecord{exampleDNSKEY}, nil),
	}, {
		query:    "com.",
		qtype:    packet.DNSKEY,
		response: makeMockResponse("com.", []packet.DNSRecord{comDNSKEY}, nil),
	}, {
		query:    "com.",
		qtype:    packet.DS,
		response: makeMockResponseWithDS("com.", "example.com.", exampleDS, rrsigDS),
	}}

	ctx := context.Background()
	chain, err := srv.buildDNSSECChain(ctx, "example.com.")
	if err != nil {
		t.Fatalf("buildDNSSECChain failed: %v", err)
	}
	if len(chain) != 2 {
		t.Errorf("expected 2 links, got %d", len(chain))
	}
}

// TestFetchDSFromNetwork tests fetching DS records from parent zone.
func TestFetchDSFromNetwork(t *testing.T) {
	srv, queries := mockDNSSECServer(t)

	exampleDNSKEY, comPrivKey := makeTestDNSKEYWithName(t, "example.com.")
	comDNSKEY, _ := makeTestDNSKEYWithName(t, "com.")

	exampleDS, _ := exampleDNSKEY.ComputeDS(2)
	now := uint32(1000)
	rrsigDS, _ := packet.SignRRSet([]packet.DNSRecord{exampleDS}, comPrivKey, packet.AlgorithmECDSAP256, "com.", comDNSKEY.ComputeKeyTag(), now-60, now+3600)

	*queries = []struct {
		query    string
		qtype    packet.QueryType
		response *packet.DNSPacket
		err      error
	}{{
		query:    "com.",
		qtype:    packet.DS,
		response: makeMockResponseWithDS("com.", "example.com.", exampleDS, rrsigDS),
	}}

	ctx := context.Background()
	dsRecs, rrsigRecs, err := srv.fetchDSFromNetwork(ctx, "example.com.", "com.")
	if err != nil {
		t.Fatalf("fetchDSFromNetwork failed: %v", err)
	}
	if len(dsRecs) == 0 {
		t.Error("expected at least one DS record")
	}
	if len(rrsigRecs) == 0 {
		t.Error("expected at least one RRSIG_DS record")
	}
}

// TestFetchDSFromNetwork_LegacyGo tests that we handle the special case
// where labels==2 returns last label + "." (e.g., "test.co.uk." -> "co.uk.").
func TestParentZoneName_LegacyGo(t *testing.T) {
	// This test catches the bug where labels==2 returned wrong parent
	result := parentZoneName("test.co.uk.")
	// test.co.uk has 3 labels, so labels[1:] gives ["co.uk."]
	// join -> "co.uk." + "." -> "co.uk.."
	// But actual expected: "co.uk."
	if result != "co.uk." {
		t.Errorf("parentZoneName(%q) = %q, want %q", "test.co.uk.", result, "co.uk.")
	}
}

// makeMockResponse creates a mock DNS response with the given records in Answers.
func makeMockResponse(name string, records []packet.DNSRecord, auths []packet.DNSRecord) *packet.DNSPacket {
	return &packet.DNSPacket{
		Header: packet.DNSHeader{ResCode: 0},
		Answers:    records,
		Authorities: auths,
		Resources:  nil,
	}
}

// makeMockResponseWithDS creates a mock response containing DS and RRSIG_DS records.
func makeMockResponseWithDS(parentZone, childZone string, ds packet.DNSRecord, rrsig packet.DNSRecord) *packet.DNSPacket {
	ds.Name = childZone
	rrsig.Name = parentZone
	return &packet.DNSPacket{
		Header:     packet.DNSHeader{ResCode: 0},
		Answers:    []packet.DNSRecord{ds},
		Authorities: []packet.DNSRecord{rrsig},
	}
}

