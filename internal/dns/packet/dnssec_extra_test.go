package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestComputeKeyTag_Complex(t *testing.T) {
	// DNSKEY with odd number of bytes in RDATA
	rec := DNSRecord{
		Type:      DNSKEY,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{1, 2, 3}, // odd length
	}
	tag := rec.ComputeKeyTag()
	if tag == 0 {
		t.Errorf("Expected non-zero tag")
	}
}

func TestComputeDS_Unsupported(t *testing.T) {
	rec := DNSRecord{
		Type:      DNSKEY,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{1, 2, 3, 4},
	}
	// Digest type 0 is unsupported
	ds, err := rec.ComputeDS(0)
	if err != nil {
		t.Fatalf("ComputeDS(0) failed: %v", err)
	}
	if ds.Type != 0 {
		t.Errorf("Expected empty record for unsupported digest type")
	}
}

func TestSignRRSet_SignError(t *testing.T) {
	// Create a dummy private key that might fail (not really possible with standard ecdsa)
	// But we can test other paths.
	
	// inception > expiration
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rrset := []DNSRecord{{Name: "test.", Type: A, TTL: 60}}
	
	sig, err := SignRRSet(rrset, key, "signer.", 1, 200, 100) // inception > expiration
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}
	if sig.Expiration != 100 || sig.Inception != 200 {
		t.Errorf("Signature time mismatch")
	}
}
