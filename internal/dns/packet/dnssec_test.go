package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

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

func TestComputeDS(t *testing.T) {
	record := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	ds, err := record.ComputeDS(2) // SHA-256
	if errScan != nil {
		t.Fatalf("ComputeDS failed: %v", err)
	}
	if ds.Type != DS || len(ds.Digest) == 0 {
		t.Errorf("Invalid DS record generated")
	}
}

func TestSignRRSet(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	records := []DNSRecord{
		{Name: "www.test.", Type: A, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}
	
	sig, err := SignRRSet(records, privKey, "test.", 1234, 1600000000, 1700000000)
	if errScan != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}
	
	if sig.Type != RRSIG || len(sig.Signature) != 64 {
		t.Errorf("Invalid RRSIG generated")
	}
}

func TestComputeKeyTag_WrongType(t *testing.T) {
	record := DNSRecord{Type: A}
	if tag := record.ComputeKeyTag(); tag != 0 {
		t.Errorf("Expected 0 tag for non-DNSKEY")
	}
}

func TestComputeDS_WrongType(t *testing.T) {
	record := DNSRecord{Type: A}
	ds, err := record.ComputeDS(2)
	if err != nil || ds.Type != UNKNOWN {
		t.Errorf("Expected empty record and no error for non-DNSKEY")
	}
}

func TestSignRRSet_Empty(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := SignRRSet([]DNSRecord{}, priv, "test.", 0, 0, 0)
	if err != nil || sig.Type != UNKNOWN {
		t.Errorf("Expected empty record for empty RRSet")
	}
}
