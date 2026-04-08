package packet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestDNSRecord_ReadWrite_DNSKEY(t *testing.T) {
	record := DNSRecord{
		Name:      "example.com.",
		Type:      DNSKEY,
		TTL:       3600,
		Flags:     256,
		Algorithm: 13,
		PublicKey: []byte{1, 2, 3, 4, 5, 6},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.Flags != 256 || parsed.Algorithm != 13 || string(parsed.PublicKey) != string(record.PublicKey) {
		t.Errorf("DNSKEY mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_DS(t *testing.T) {
	record := DNSRecord{
		Name:       "example.com.",
		Type:       DS,
		TTL:        3600,
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.KeyTag != 12345 || parsed.Algorithm != 13 || parsed.DigestType != 2 || string(parsed.Digest) != string(record.Digest) {
		t.Errorf("DS mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_RRSIG(t *testing.T) {
	record := DNSRecord{
		Name:        "example.com.",
		Type:        RRSIG,
		TTL:         3600,
		TypeCovered: uint16(A),
		Algorithm:   13,
		Labels:      2,
		OrigTTL:     3600,
		Expiration:  2000000000,
		Inception:   1000000000,
		KeyTag:      123,
		SignerName:  "example.com.",
		Signature:   []byte{1, 2, 3, 4},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.TypeCovered != uint16(A) || parsed.KeyTag != 123 || parsed.SignerName != "example.com." {
		t.Errorf("RRSIG mismatch: %+v", parsed)
	}
}

func TestDNSRecord_ReadWrite_NSEC(t *testing.T) {
	record := DNSRecord{
		Name:       "a.example.com.",
		Type:       NSEC,
		TTL:        3600,
		NextName:   "z.example.com.",
		TypeBitMap: []byte{0, 1, 2},
	}

	buffer := NewBytePacketBuffer()
	_, _ = record.Write(buffer)
	_ = buffer.Seek(0)
	
	parsed := DNSRecord{}
	_ = parsed.Read(buffer)
	
	if parsed.NextName != "z.example.com." || string(parsed.TypeBitMap) != string(record.TypeBitMap) {
		t.Errorf("NSEC mismatch: %+v", parsed)
	}
}

func TestSignRRSet_Simple(t *testing.T) {
	rrset := []DNSRecord{
		{Name: "test.com.", Type: A, IP: []byte{1, 2, 3, 4}, TTL: 300, Class: 1},
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	
	sig, err := SignRRSet(rrset, priv, "test.com.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed: %v", err)
	}
	if sig.Type != RRSIG || sig.KeyTag != 1234 {
		t.Errorf("Invalid signature record: %+v", sig)
	}
}

func TestCountLabels_Root(t *testing.T) {
	if c := countLabels("."); c != 0 {
		t.Errorf("Expected 0 labels for root, got %d", c)
	}
}

func TestComputeDS_Paths(t *testing.T) {
	// 1. Non-DNSKEY record
	rec := DNSRecord{Type: A}
	ds, err := rec.ComputeDS(1)
	if err != nil || ds.Type != 0 {
		t.Errorf("Expected empty record for non-DNSKEY, got %+v", ds)
	}

	// 2. DNSKEY with SHA-1
	key := DNSRecord{
		Name: "test.", Type: DNSKEY, Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3},
	}
	ds1, err := key.ComputeDS(1)
	if err != nil || ds1.DigestType != 1 || len(ds1.Digest) == 0 {
		t.Errorf("SHA-1 DS computation failed: %+v", ds1)
	}

	// 3. DNSKEY with invalid digest type
	ds0, err := key.ComputeDS(99)
	if err != nil || ds0.Type != 0 {
		t.Errorf("Expected empty record for invalid digest type")
	}
}
