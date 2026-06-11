package config

import (
	"testing"
)

func TestParseTrustAnchor(t *testing.T) {
	// Test invalid base64
	_, err := ParseTrustAnchor("not-valid-base64!!!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Test too short
	_, err = ParseTrustAnchor("AAAB")
	if err == nil {
		t.Error("Expected error for too short data")
	}

	// Test valid trust anchor (valid base64, >= 4 bytes)
	// 4 bytes: flags=0x0100, protocol=1, algorithm=13 (ECDSA P-256), rest is public key
	validAnchor := "AQANAA=="
	dnskey, err := ParseTrustAnchor(validAnchor)
	if err != nil {
		t.Errorf("Expected no error for valid anchor, got: %v", err)
	}
	if dnskey.Type != 48 { // DNSKEY type
		t.Errorf("Expected type48 (DNSKEY), got %d", dnskey.Type)
	}
	if dnskey.Algorithm != 13 {
		t.Errorf("Expected algorithm 13, got %d", dnskey.Algorithm)
	}
}

func TestDNSSECConfigToMap(t *testing.T) {
	// Test error path with invalid anchor
	cfg := &DNSSECConfig{
		Mode: "ad-bit-only",
		TrustAnchors: map[string]string{
			"test.": "INVALID",
		},
	}
	_, err := cfg.ToMap()
	if err == nil {
		t.Error("Expected error for invalid trust anchor")
	}

	// Test success path with valid anchor
	validAnchor := "AQANAA=="
	cfg2 := &DNSSECConfig{
		Mode: "strict",
		TrustAnchors: map[string]string{
			"example.com.": validAnchor,
		},
	}
	result, err := cfg2.ToMap()
	if err != nil {
		t.Errorf("Expected no error for valid anchor, got: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result))
	}
	if _, ok := result["example.com."]; !ok {
		t.Error("Expected result to contain example.com.")
	}
}