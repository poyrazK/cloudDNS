package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestComputeKeyTag verifies that the key tag calculation (RFC 4034 Appendix B)
// produces a valid non-zero result for a standard DNSKEY.
func TestComputeKeyTag(t *testing.T) {
	record := DNSRecord{
		Type:      DNSKEY,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	tag := record.ComputeKeyTag()
	if tag == 0 {
		t.Errorf("Expected non-zero key tag")
	}
}

// TestComputeDS validates the generation of Delegation Signer (DS) records
// from a DNSKEY using various digest algorithms.
func TestComputeDS(t *testing.T) {
	record := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	// Test SHA-256 (Type 2)
	ds, err := record.ComputeDS(2) 
	if err != nil {
		t.Fatalf("ComputeDS failed: %v", err)
	}
	if ds.Type != DS || len(ds.Digest) == 0 {
		t.Errorf("Invalid DS record generated for SHA-256")
	}
	
	// Test SHA-1 (Type 1)
	ds1, _ := record.ComputeDS(1)
	if len(ds1.Digest) == 0 { 
		t.Errorf("Invalid DS record generated for SHA-1") 
	}
}

// TestSignRRSet_ECDSA ensures that an RRSet can be correctly signed using 
// an ECDSA P-256 private key to produce a valid RRSIG.
func TestSignRRSet_ECDSA(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	records := []DNSRecord{
		{Name: "www.test.", Type: A, TTL: 300, IP: []byte{1, 2, 3, 4}, Class: 1},
	}
	
	sig, err := SignRRSet(records, privKey, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}
	
	if sig.Type != RRSIG || len(sig.Signature) != 64 {
		t.Errorf("Invalid RRSIG generated for ECDSA P-256")
	}
}

// TestComputeKeyTag_WrongType ensures that key tag computation correctly
// ignores non-DNSKEY records.
func TestComputeKeyTag_WrongType(t *testing.T) {
	record := DNSRecord{Type: A}
	if tag := record.ComputeKeyTag(); tag != 0 {
		t.Errorf("Expected 0 tag for non-DNSKEY")
	}
}

// TestComputeDS_WrongType ensures that DS record generation correctly
// handles non-DNSKEY input by returning an empty record.
func TestComputeDS_WrongType(t *testing.T) {
	record := DNSRecord{Type: A}
	ds, err := record.ComputeDS(2)
	if err != nil || ds.Type != UNKNOWN {
		t.Errorf("Expected empty record and no error for non-DNSKEY")
	}
}

// TestSignRRSet_EmptyRRSet validates that attempting to sign an empty RRSet
// correctly returns an empty record.
func TestSignRRSet_EmptyRRSet(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := SignRRSet([]DNSRecord{}, priv, "test.", 0, 0, 0)
	if err != nil || sig.Type != UNKNOWN {
		t.Errorf("Expected empty record for empty RRSet")
	}
}

// TestComputeDS_InvalidAlgID ensures that unsupported digest algorithms
// result in an empty digest without returning an error.
func TestComputeDS_InvalidAlgID(t *testing.T) {
	record := DNSRecord{Type: DNSKEY, Name: "test.", PublicKey: []byte{1}}
	ds, err := record.ComputeDS(99) // 99 is not a standard digest ID
	if err != nil {
		t.Fatalf("ComputeDS should not return error for unsupported alg")
	}
	if len(ds.Digest) != 0 {
		t.Errorf("Expected empty digest for unsupported algorithm")
	}
}
