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
}

func TestDNSSECConfigToMap(t *testing.T) {
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
}