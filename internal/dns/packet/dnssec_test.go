package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestDNSSEC_SignAndVerify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	records := []DnsRecord{
		{Name: "example.com.", Type: A, TTL: 3600},
	}

	inception := uint32(1700000000)
	expiration := inception + 3600
	signer := "example.com."
	keyTag := uint16(12345)

	sig, err := SignRRSet(records, privKey, signer, keyTag, inception, expiration)
	if err != nil {
		t.Fatalf("Failed to sign RRSet: %v", err)
	}

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

func TestDNSSEC_ComputeKeyTag(t *testing.T) {
	record := DnsRecord{
		Type:      DNSKEY,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}

	tag := record.ComputeKeyTag()
	if tag == 0 {
		t.Errorf("KeyTag should not be 0")
	}

	// Non-DNSKEY should return 0
	record.Type = A
	if record.ComputeKeyTag() != 0 {
		t.Errorf("Non-DNSKEY should return tag 0")
	}
}

func TestDNSSEC_SignEmptyRRSet(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := SignRRSet([]DnsRecord{}, privKey, "test.", 1, 0, 0)
	if err != nil || sig.Type != UNKNOWN {
		t.Errorf("Empty RRSet should return empty record and no error")
	}
}
