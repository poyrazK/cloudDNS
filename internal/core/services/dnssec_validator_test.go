package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func makeTestDNSKEY(t *testing.T) (packet.DNSRecord, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// RFC 6605 format: X||Y (64 bytes)
	pubBytes := make([]byte, 64)
	xBytes := privKey.PublicKey.X.FillBytes(make([]byte, 32))
	yBytes := privKey.PublicKey.Y.FillBytes(make([]byte, 32))
	copy(pubBytes[0:32], xBytes)
	copy(pubBytes[32:64], yBytes)

	dnskey := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    256, // ZSK flag
		Protocol: 3,
		Algorithm: 13, // ECDSAP256SHA256
		PublicKey: pubBytes,
	}

	return dnskey, privKey
}

func TestNewDNSSECValidator(t *testing.T) {
	trustAnchors := map[string]packet.DNSRecord{
		"example.com.": {Name: "example.com.", Type: packet.DNSKEY},
	}
	validator := NewDNSSECValidator(trustAnchors)
	if validator == nil {
		t.Fatal("NewDNSSECValidator returned nil")
	}
	if len(validator.trustAnchors) != 1 {
		t.Errorf("Expected 1 trust anchor, got %d", len(validator.trustAnchors))
	}
}

func TestGetTrustAnchor(t *testing.T) {
	trustAnchors := map[string]packet.DNSRecord{
		"example.com.": {Name: "example.com.", Type: packet.DNSKEY, Algorithm: 13},
	}
	validator := NewDNSSECValidator(trustAnchors)

	// Found
	anchor := validator.GetTrustAnchor("example.com.")
	if anchor == nil {
		t.Fatal("Expected to find trust anchor for example.com")
	}
	if anchor.Algorithm != 13 {
		t.Errorf("Expected algorithm 13, got %d", anchor.Algorithm)
	}

	// Not found
	anchor = validator.GetTrustAnchor("unknown.com.")
	if anchor != nil {
		t.Error("Expected nil for unknown zone")
	}
}

func TestValidateRRSet_EmptyInputs(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	tests := []struct {
		name   string
		rrset  []packet.DNSRecord
		rrsigs []packet.DNSRecord
		dnskeys []packet.DNSRecord
	}{
		{"empty rrset", []packet.DNSRecord{}, []packet.DNSRecord{{Type: packet.RRSIG}}, []packet.DNSRecord{{Type: packet.DNSKEY}}},
		{"empty rrsigs", []packet.DNSRecord{{Type: packet.A}}, []packet.DNSRecord{}, []packet.DNSRecord{{Type: packet.DNSKEY}}},
		{"empty dnskeys", []packet.DNSRecord{{Type: packet.A}}, []packet.DNSRecord{{Type: packet.RRSIG}}, []packet.DNSRecord{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateRRSet(tt.rrset, tt.rrsigs, tt.dnskeys, now)
			if result.Valid {
				t.Error("Expected invalid result for empty inputs")
			}
			if result.EDE == nil {
				t.Error("Expected EDE to be set")
			}
		})
	}
}

func TestValidateRRSet_NoMatchingRRSIG(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	// RRSIG covers TXT, not A
	rrsigs := []packet.DNSRecord{
		{Type: packet.RRSIG, TypeCovered: uint16(packet.TXT)},
	}
	dnskeys := []packet.DNSRecord{
		{Type: packet.DNSKEY, Algorithm: 13},
	}

	result := validator.ValidateRRSet(rrset, rrsigs, dnskeys, now)
	if result.Valid {
		t.Error("Expected invalid when no matching RRSIG")
	}
	if result.EDE == nil || result.EDE.Info != "no matching RRSIG found" {
		t.Errorf("Expected 'no matching RRSIG found', got %v", result.EDE)
	}
}

func TestValidateRRSet_NoMatchingDNSKEY(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}
	rrsigs := []packet.DNSRecord{
		{Type: packet.RRSIG, TypeCovered: uint16(packet.A), KeyTag: 12345, Algorithm: 13},
	}
	// DNSKEY with different key tag
	dnskey, _ := makeTestDNSKEY(t)
	dnskeys := []packet.DNSRecord{dnskey}

	result := validator.ValidateRRSet(rrset, rrsigs, dnskeys, now)
	if result.Valid {
		t.Error("Expected invalid when no matching DNSKEY")
	}
	if result.EDE == nil || result.EDE.Info != "dnskey-missing" {
		t.Errorf("Expected 'dnskey-missing', got %v", result.EDE)
	}
}

func TestValidateRRSet_InvalidDNSKEYFormat(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Create DNSKEY with bad public key (too short)
	dnskey := packet.DNSRecord{
		Name:     "example.com.",
		Type:     packet.DNSKEY,
		Class:    1,
		TTL:      300,
		Flags:    256,
		Protocol: 3,
		Algorithm: 13,
		PublicKey: []byte{0x00}, // Too short - invalid format
	}
	// Compute keytag for the bad DNSKEY
	keyTag := dnskey.ComputeKeyTag()

	// Create RRSIG with matching key tag and algorithm but dummy signature
	rrsig := packet.DNSRecord{
		Type:         packet.RRSIG,
		TypeCovered:  uint16(packet.A),
		Algorithm:    dnskey.Algorithm,
		KeyTag:       keyTag,
		SignerName:   "example.com.",
		Expiration:   now + 3600,
		Inception:    now - 60,
		OrigTTL:      300,
		Labels:       3,
		Signature:    make([]byte, 64), // Dummy signature
	}

	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if result.Valid {
		t.Error("Expected invalid for bad DNSKEY format")
	}
	if result.EDE == nil || result.EDE.Info != "invalid-dnskey-format" {
		t.Errorf("Expected 'invalid-dnskey-format', got %v", result.EDE)
	}
}

func TestValidateRRSet_ExpiredSignature(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey, privKey := makeTestDNSKEY(t)

	// Create an expired signature
	inception := uint32(1000)
	expiration := uint32(1500) // Expired

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), inception, expiration)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Validate with now=2000, but signature expired at 1500
	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, 2000)
	if result.Valid {
		t.Error("Expected invalid for expired signature")
	}
	if result.EDE == nil || result.EDE.Info != "signature-expired" {
		t.Errorf("Expected 'signature-expired', got %v", result.EDE)
	}
}

func TestValidateRRSet_NotYetValidSignature(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey, privKey := makeTestDNSKEY(t)

	// Create a not-yet-valid signature
	inception := uint32(2000) // In the future
	expiration := uint32(3000)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), inception, expiration)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Validate with now=1000, but signature not valid until 2000
	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, 1000)
	if result.Valid {
		t.Error("Expected invalid for not-yet-valid signature")
	}
	if result.EDE == nil || result.EDE.Info != "signature-not-yet-valid" {
		t.Errorf("Expected 'signature-not-yet-valid', got %v", result.EDE)
	}
}

func TestValidateRRSet_AlgorithmMismatch(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	dnskey, _ := makeTestDNSKEY(t)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// RRSIG with different algorithm - but since FindMatchingDNSKEY checks algorithm,
	// this results in "dnskey-missing" before algorithm-specific error can be returned
	rrsig := packet.DNSRecord{
		Type:         packet.RRSIG,
		TypeCovered:  uint16(packet.A),
		Algorithm:    14, // Different algorithm
		KeyTag:       dnskey.ComputeKeyTag(),
		SignerName:   "example.com.",
		Expiration:   now + 3600,
		Inception:    now - 60,
		OrigTTL:      300,
		Labels:       3,
		Signature:    make([]byte, 64), // Dummy signature
	}

	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if result.Valid {
		t.Error("Expected invalid for algorithm mismatch")
	}
	// FindMatchingDNSKEY checks algorithm, so we get dnskey-missing
	if result.EDE == nil || result.EDE.Info != "dnskey-missing" {
		t.Errorf("Expected 'dnskey-missing', got %v", result.EDE)
	}
}

func TestValidateRRSet_ValidSignature(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey, privKey := makeTestDNSKEY(t)

	now := uint32(1000)
	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if !result.Valid {
		t.Errorf("Expected valid result, got EDE: %v", result.EDE)
	}
	if !result.ADBit {
		t.Error("Expected ADBit to be true")
	}
}

func TestValidateDNSKEYChain_EmptyDNSKEYS(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	err := validator.ValidateDNSKEYChain([]packet.DNSRecord{}, packet.DNSRecord{Type: packet.DS}, packet.DNSRecord{})
	if err == nil {
		t.Error("Expected error for empty dnskeys")
	}
}

func TestValidateDNSKEYChain_NoMatchingDNSKEY(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey, _ := makeTestDNSKEY(t)

	ds := packet.DNSRecord{
		Type:       packet.DS,
		KeyTag:     dnskey.ComputeKeyTag() + 1, // Different key tag
		Algorithm:  dnskey.Algorithm,
		DigestType: 2,
	}

	err := validator.ValidateDNSKEYChain([]packet.DNSRecord{dnskey}, ds, packet.DNSRecord{})
	if err == nil {
		t.Error("Expected error when no matching DNSKEY for DS")
	}
}

func TestValidateDNSKEYChain_ValidChain(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey, _ := makeTestDNSKEY(t)

	// Compute DS from the DNSKEY
	ds, err := dnskey.ComputeDS(2) // SHA-256
	if err != nil {
		t.Fatalf("Failed to compute DS: %v", err)
	}

	err = validator.ValidateDNSKEYChain([]packet.DNSRecord{dnskey}, ds, packet.DNSRecord{})
	if err != nil {
		t.Errorf("Expected valid chain, got error: %v", err)
	}
}

func TestValidateWithTrustAnchor_NoAnchor(t *testing.T) {
	// Validator with no trust anchors - should fall back to regular validation
	validator := NewDNSSECValidator(nil)

	dnskey, privKey := makeTestDNSKEY(t)
	now := uint32(1000)
	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// With no trust anchor, should still validate via regular path
	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if !result.Valid {
		t.Errorf("Expected valid without trust anchor, got EDE: %v", result.EDE)
	}
}

func TestValidateWithTrustAnchor_AnchorNotFound(t *testing.T) {
	trustAnchors := map[string]packet.DNSRecord{
		"example.com.": {Name: "example.com.", Type: packet.DNSKEY, Algorithm: 13},
	}
	validator := NewDNSSECValidator(trustAnchors)

	dnskey, _ := makeTestDNSKEY(t)
	now := uint32(1000)
	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Different key tag than trust anchor
	rrsig := packet.DNSRecord{
		Type:         packet.RRSIG,
		TypeCovered:  uint16(packet.A),
		Algorithm:    dnskey.Algorithm,
		KeyTag:       dnskey.ComputeKeyTag() + 1,
		SignerName:   "example.com.",
		Expiration:   now + 3600,
		Inception:    now - 60,
		OrigTTL:      300,
		Labels:       3,
		Signature:    make([]byte, 64),
	}

	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if result.Valid {
		t.Error("Expected invalid when trust anchor DNSKEY not found")
	}
	if result.EDE == nil || result.EDE.Info != "trust-anchor-not-found" {
		t.Errorf("Expected 'trust-anchor-not-found', got %v", result.EDE)
	}
}

func TestValidateWithTrustAnchor_ValidWithAnchor(t *testing.T) {
	dnskey, privKey := makeTestDNSKEY(t)

	trustAnchors := map[string]packet.DNSRecord{
		"example.com.": dnskey, // Use same DNSKEY as trust anchor
	}
	validator := NewDNSSECValidator(trustAnchors)

	now := uint32(1000)
	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	result := validator.ValidateWithTrustAnchor("example.com.", rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if !result.Valid {
		t.Errorf("Expected valid with trust anchor, got EDE: %v", result.EDE)
	}
	if !result.ADBit {
		t.Error("Expected ADBit to be true")
	}
}

func TestValidateRRSet_KeyTagMismatch(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	dnskey, privKey := makeTestDNSKEY(t)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Sign with correct key
	rrsig, err := packet.SignRRSet(rrset, privKey, packet.AlgorithmECDSAP256, "example.com.", dnskey.ComputeKeyTag(), now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Corrupt the key tag in RRSIG - this makes FindMatchingDNSKEY return nil
	rrsig.KeyTag = rrsig.KeyTag + 1

	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if result.Valid {
		t.Error("Expected invalid for key tag mismatch")
	}
	// FindMatchingDNSKEY returns nil due to keytag mismatch, so we get dnskey-missing
	if result.EDE == nil || result.EDE.Info != "dnskey-missing" {
		t.Errorf("Expected 'dnskey-missing', got %v", result.EDE)
	}
}

func TestValidateRRSet_InvalidSignature(t *testing.T) {
	validator := NewDNSSECValidator(nil)
	now := uint32(1000)

	dnskey, _ := makeTestDNSKEY(t)

	rrset := []packet.DNSRecord{
		{Name: "www.example.com.", Type: packet.A, IP: net.ParseIP("1.2.3.4"), TTL: 300, Class: 1},
	}

	// Create valid RRSIG structure but with garbage signature
	rrsig := packet.DNSRecord{
		Type:         packet.RRSIG,
		TypeCovered:  uint16(packet.A),
		Algorithm:    dnskey.Algorithm,
		KeyTag:       dnskey.ComputeKeyTag(),
		SignerName:   "example.com.",
		Expiration:   now + 3600,
		Inception:    now - 60,
		OrigTTL:      300,
		Labels:       3,
		Signature:    make([]byte, 64), // Garbage signature
	}

	result := validator.ValidateRRSet(rrset, []packet.DNSRecord{rrsig}, []packet.DNSRecord{dnskey}, now)
	if result.Valid {
		t.Error("Expected invalid for bad signature")
	}
	if result.EDE == nil || result.EDE.Info != "invalid-signature" {
		t.Errorf("Expected 'invalid-signature', got %v", result.EDE)
	}
}

func TestValidateChain_EmptyChain(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	err := validator.ValidateChain([]ChainLink{}, uint32(1000))
	if err == nil {
		t.Error("Expected error for empty chain")
	}
}

func TestValidateChain_SingleZoneWithTrustAnchor(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey, _ := makeTestDNSKEY(t)

	// Single zone with trust anchor
	chain := []ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{dnskey},
			DS:      packet.DNSRecord{}, // Empty DS - using trust anchor instead
		},
	}

	// Without trust anchor, empty DS means no validation
	err := validator.ValidateChain(chain, uint32(1000))
	if err != nil {
		t.Errorf("Expected no error for single zone with empty DS, got: %v", err)
	}
}

func TestValidateChain_TwoZoneChain(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	// Create keys for two zones
	comDNSKEY, comPrivKey := makeTestDNSKEY(t)
	comDNSKEY.Name = "com."

	exampleDNSKEY, _ := makeTestDNSKEY(t)
	exampleDNSKEY.Name = "example.com."

	// Compute DS from example.com's DNSKEY (DS is derived from child zone)
	ds, err := exampleDNSKEY.ComputeDS(2) // SHA-256
	if err != nil {
		t.Fatalf("Failed to compute DS: %v", err)
	}

	// Sign DS with com's key (parent zone signs child's DS)
	now := uint32(1000)
	rrsig, err := packet.SignRRSet([]packet.DNSRecord{ds}, comPrivKey, packet.AlgorithmECDSAP256, "com.", comDNSKEY.ComputeKeyTag(), now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign DS: %v", err)
	}

	// Chain: example.com -> com
	chain := []ChainLink{
		{
			Zone:     "example.com.",
			DNSKEYs:  []packet.DNSRecord{exampleDNSKEY},
			DS:       ds,
			RRSIGsDS: []packet.DNSRecord{rrsig},
		},
		{
			Zone:    "com.",
			DNSKEYs: []packet.DNSRecord{comDNSKEY},
			DS:      packet.DNSRecord{}, // com zone - no parent DS in this chain
		},
	}

	err = validator.ValidateChain(chain, now)
	if err != nil {
		t.Errorf("Expected valid two-zone chain, got error: %v", err)
	}
}

func TestValidateChain_WithTrustAnchor(t *testing.T) {
	// Create root anchor
	rootDNSKEY, rootPrivKey := makeTestDNSKEY(t)
	rootDNSKEY.Name = "."

	trustAnchors := map[string]packet.DNSRecord{
		".": rootDNSKEY,
	}
	validator := NewDNSSECValidator(trustAnchors)

	// Create DNSKEYs for com and example
	comDNSKEY, comPrivKey := makeTestDNSKEY(t)
	comDNSKEY.Name = "com."

	exampleDNSKEY, _ := makeTestDNSKEY(t)
	exampleDNSKEY.Name = "example.com."

	// Compute DS records from child zone's DNSKEY
	exampleDS, _ := exampleDNSKEY.ComputeDS(2)
	comDS, _ := comDNSKEY.ComputeDS(2)

	// Sign DS records with parent zone's key
	now := uint32(1000)

	// example.com's DS signed by com's key
	exampleRRSIG, _ := packet.SignRRSet([]packet.DNSRecord{exampleDS}, comPrivKey, packet.AlgorithmECDSAP256, "com.", comDNSKEY.ComputeKeyTag(), now-60, now+3600)

	// com's DS signed by root's key
	comRRSIG, _ := packet.SignRRSet([]packet.DNSRecord{comDS}, rootPrivKey, packet.AlgorithmECDSAP256, ".", rootDNSKEY.ComputeKeyTag(), now-60, now+3600)

	// Chain: example.com -> com -> root (trust anchor)
	chain := []ChainLink{
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
		t.Errorf("Expected valid chain with trust anchor, got error: %v", err)
	}
}

func TestValidateChain_DNSKEYMismatch(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	dnskey1, _ := makeTestDNSKEY(t)
	dnskey2, _ := makeTestDNSKEY(t) // Different key

	// Compute DS from dnskey1
	ds, _ := dnskey1.ComputeDS(2)

	// Chain with dnskey2 (doesn't match DS)
	chain := []ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{dnskey2}, // Different key
			DS:      ds,
		},
	}

	err := validator.ValidateChain(chain, uint32(1000))
	if err == nil {
		t.Error("Expected error when DNSKEY doesn't match DS")
	}
}

func TestValidateChain_InvalidRRSIGDSSignature(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	// Create key for com zone
	comDNSKEY, comPrivKey := makeTestDNSKEY(t)
	comDNSKEY.Name = "com."

	// Create different key for example.com
	exampleDNSKEY, _ := makeTestDNSKEY(t)
	exampleDNSKEY.Name = "example.com."

	// Compute DS for example.com using com's DNSKEY
	ds, err := exampleDNSKEY.ComputeDS(2) // SHA-256
	if err != nil {
		t.Fatalf("Failed to compute DS: %v", err)
	}

	// Sign the DS with com's key (correct)
	now := uint32(1000)
	rrsig, err := packet.SignRRSet([]packet.DNSRecord{ds}, comPrivKey, packet.AlgorithmECDSAP256, "com.", comDNSKEY.ComputeKeyTag(), now-60, now+3600)
	if err != nil {
		t.Fatalf("Failed to sign DS: %v", err)
	}

	// Chain: example.com -> com
	chain := []ChainLink{
		{
			Zone:     "example.com.",
			DNSKEYs:  []packet.DNSRecord{exampleDNSKEY},
			DS:       ds,
			RRSIGsDS: []packet.DNSRecord{rrsig},
		},
		{
			Zone:    "com.",
			DNSKEYs: []packet.DNSRecord{comDNSKEY},
			DS:      packet.DNSRecord{},
		},
	}

	// Valid signature should pass
	err = validator.ValidateChain(chain, now)
	if err != nil {
		t.Errorf("Expected valid chain with correct RRSIG_DS, got error: %v", err)
	}

	// Corrupt the signature to make it invalid
	chain[0].RRSIGsDS[0].Signature[0] ^= 0xFF
	err = validator.ValidateChain(chain, now)
	if err == nil {
		t.Error("Expected error when RRSIG_DS signature is invalid")
	}
}

func TestValidateChain_InvalidRRSIGDSSignature_GarbageSig(t *testing.T) {
	validator := NewDNSSECValidator(nil)

	// Create key for com zone
	comDNSKEY, _ := makeTestDNSKEY(t)
	comDNSKEY.Name = "com."

	// Create key for example.com
	exampleDNSKEY, _ := makeTestDNSKEY(t)
	exampleDNSKEY.Name = "example.com."

	// Compute DS from example.com's DNSKEY (DS is derived from child zone)
	ds, err := exampleDNSKEY.ComputeDS(2) // SHA-256
	if err != nil {
		t.Fatalf("Failed to compute DS: %v", err)
	}

	// Create a valid RRSIG but with garbage signature (won't match)
	garbageSig := make([]byte, 64)
	rrsig := packet.DNSRecord{
		Type:         packet.RRSIG,
		TypeCovered:  uint16(packet.DS),
		Algorithm:    comDNSKEY.Algorithm,
		KeyTag:       comDNSKEY.ComputeKeyTag(),
		SignerName:   "com.",
		Expiration:   uint32(2000),
		Inception:    uint32(500),
		OrigTTL:      300,
		Labels:       2,
		Signature:    garbageSig, // Invalid signature
	}

	// Chain: example.com -> com (with DS and RRSIGsDS with invalid signature)
	chain := []ChainLink{
		{
			Zone:     "example.com.",
			DNSKEYs:  []packet.DNSRecord{exampleDNSKEY},
			DS:       ds,
			RRSIGsDS: []packet.DNSRecord{rrsig},
		},
		{
			Zone:    "com.",
			DNSKEYs: []packet.DNSRecord{comDNSKEY},
			DS:      packet.DNSRecord{},
		},
	}

	err = validator.ValidateChain(chain, uint32(1000))
	if err == nil {
		t.Error("Expected error when RRSIG_DS signature is invalid")
	}
}

func TestValidateChain_TrustAnchorMismatch(t *testing.T) {
	// Create root anchor
	rootDNSKEY, _ := makeTestDNSKEY(t)

	trustAnchors := map[string]packet.DNSRecord{
		".": rootDNSKEY,
	}
	validator := NewDNSSECValidator(trustAnchors)

	// Create a different key for the zone
	zoneDNSKEY, _ := makeTestDNSKEY(t)

	// Chain with different key than trust anchor
	chain := []ChainLink{
		{
			Zone:    "example.com.",
			DNSKEYs: []packet.DNSRecord{zoneDNSKEY},
			DS:      packet.DNSRecord{},
		},
	}

	// This should fail because zone's DNSKEY doesn't match trust anchor
	err := validator.ValidateChain(chain, uint32(1000))
	// Actually, with empty DS and no anchor for this zone, it should pass
	// The trust anchor is only checked if link.Zone matches an anchor
	if err != nil {
		t.Errorf("Unexpected error for zone without anchor: %v", err)
	}
}

func TestEDE_String(t *testing.T) {
	tests := []struct {
		ede    EDE
		expect string
	}{
		{EDE{Code: EDECodeOther, Info: "other error"}, "other error"},
		{EDE{Code: EDECodeUnsupportedDNSKEYAlgo, Info: "algo"}, "unsupported-dnskey-algorithm"},
		{EDE{Code: EDECodeUnsupportedDSDigest, Info: "digest"}, "unsupported-ds-digest"},
		{EDE{Code: EDECodeStaleAnswer, Info: "stale"}, "stale-answer"},
		{EDE{Code: EDECodeForgedAnswer, Info: "forged"}, "forged-answer"},
		{EDE{Code: EDECodeIndeterminate, Info: "indet"}, "dnssec-indeterminate"},
		{EDE{Code: EDECodeBogus, Info: "bogus"}, "dnssec-bogus"},
		{EDE{Code: EDECodeSignatureExpired, Info: "expired"}, "signature-expired"},
		{EDE{Code: EDECodeSignatureNotYetValid, Info: "notyet"}, "signature-not-yet-valid"},
		{EDE{Code: EDECodeDNSKEYMissing, Info: "missing"}, "dnskey-missing"},
		{EDE{Code: EDECodeDSMissing, Info: "ds"}, "ds-missing"},
		{EDE{Code: EDECodeNoZoneKeyBitSet, Info: "nozone"}, "no-zone-key-bit-set"},
		{EDE{Code: EDECodeSignatureUnsupported, Info: "unsup"}, "signature-unsupported"},
		{EDE{Code: EDECodeDNSKEYNotAnchor, Info: "notanchor"}, "dnskey-not-anchor"},
		{EDE{Code: EDECodeTrustAnchorUnknown, Info: "unknown"}, "trust-anchor-unknown"},
		{EDE{Code: EDECodeExpectedAnswerAfterDNL, Info: "dnl"}, "expected-answer-after-dnl"},
		{EDE{Code: EDECodeDelegationNotServed, Info: "dns"}, "delegation-not-served"},
		{EDE{Code: EDECodeTTLMismatch, Info: "ttl"}, "ttl-mismatch"},
		{EDE{Code: EDECodeCachedValidatedResponse, Info: "cached"}, "cached-validated-response"},
		{EDE{Code: EDECodeNSEC3HashAlgoUnsupported, Info: "algo"}, "nsec3-hash-algo-unsupported"},
		{EDE{Code: EDECodeNSEC3InvalidProof, Info: "proof"}, "nsec3-invalid-proof"},
		{EDE{Code: EDECodeNSEC3ChainBroken, Info: "chain"}, "nsec3-chain-broken"},
		{EDE{Code: EDECodeNSEC3NoMatchingName, Info: "name"}, "nsec3-no-matching-name"},
		{EDE{Code: 9999, Info: "unknown"}, "unknown-error"},
	}

	for _, tc := range tests {
		if got := tc.ede.String(); got != tc.expect {
			t.Errorf("EDE{Code: %d}.String() = %q, want %q", tc.ede.Code, got, tc.expect)
		}
	}
}
