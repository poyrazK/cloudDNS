package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestDNSSEC_SignAndVerify(t *testing.T) {
	// 1. Generate a P-256 Key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 2. Create a dummy RRSet (single A record)
	records := []DnsRecord{
		{Name: "example.com.", Type: A, TTL: 3600},
	}

	// 3. Sign it
	inception := uint32(1700000000)
	expiration := inception + 3600
	signer := "example.com."
	keyTag := uint16(12345)

	sig, err := SignRRSet(records, privKey, signer, keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("Failed to sign RRSet: %v", err)
	}

	// 4. Verify Signature Fields
	if sig.Type != RRSIG {
		t.Errorf("Expected RRSIG, got %v", sig.Type)
	}
	if sig.TypeCovered != uint16(A) {
		t.Errorf("Expected TypeCovered A, got %d", sig.TypeCovered)
	}
	if sig.KeyTag != keyTag {
		t.Errorf("KeyTag mismatch")
	}
	if len(sig.Signature) != 64 {
		t.Errorf("Expected 64-byte signature for P-256, got %d", len(sig.Signature))
	}
}
