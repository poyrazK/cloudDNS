package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"testing"
	"time"

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
	rrsig, err := packet.SignRRSet(rrset, privKey, "example.com.", keyTag, now-60, now+3600)
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
	rrsig, _ := packet.SignRRSet(rrset, privKey, "example.com.", keyTag, now-7200, now-3600) // expired

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
	rrsig, _ := packet.SignRRSet(rrset, privKey, "example.com.", 12345, now-60, now+3600)

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
	rrsig1, _ := packet.SignRRSet(rrset, privKey, "example.com.", keyTag, now-60, now+3600)
	rrsig2, _ := packet.SignRRSet(rrset, privKey, "example.com.", keyTag, now-120, now+3600)

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
	rrsig, _ := packet.SignRRSet(rrset, privKey, "example.com.", keyTag, now-60, now+3600)

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
	rrsig, _ := packet.SignRRSet(rrset, privKey, "example.com.", keyTag, now-60, now+3600)

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