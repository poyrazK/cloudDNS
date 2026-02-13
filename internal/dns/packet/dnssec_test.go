package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestComputeKeyTag(t *testing.T) {
	record := DnsRecord{
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
	record := DnsRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		Flags:     257,
		Algorithm: 13,
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
	}
	ds, err := record.ComputeDS(2) // SHA-256
	if err != nil {
		t.Fatalf("ComputeDS failed: %v", err)
	}
	if ds.Type != DS || len(ds.Digest) == 0 {
		t.Errorf("Invalid DS record generated")
	}
}

func TestSignRRSet(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	records := []DnsRecord{
		{Name: "www.test.", Type: A, TTL: 300, IP: []byte{1, 2, 3, 4}},
	}
	
	sig, err := SignRRSet(records, privKey, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}
	
	if sig.Type != RRSIG || len(sig.Signature) != 64 {
		t.Errorf("Invalid RRSIG generated")
	}
}

func TestCountLabels(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{"example.com.", 2},
		{"www.example.com.", 3},
		{".", 0},
		{"", 0},
	}
	for _, c := range cases {
		if got := countLabels(c.name); got != c.want {
			t.Errorf("countLabels(%s) = %d, want %d", c.name, got, c.want)
		}
	}
}
