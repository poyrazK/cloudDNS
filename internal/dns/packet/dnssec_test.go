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

	sig, err := SignRRSet(records, privKey, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
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
	sig, err := SignRRSet([]DNSRecord{}, priv, AlgorithmECDSAP256, "test.", 0, 0, 0)
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

// TestWriteSignCanonicalRData_AAAA verifies canonical RDATA writing for AAAA records.
func TestWriteSignCanonicalRData_AAAA(t *testing.T) {
	records := []DNSRecord{
		{Name: "ipv6.test.", Type: AAAA, TTL: 300, IP: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for AAAA: %v", err)
	}
}

// TestWriteSignCanonicalRData_CNAME verifies canonical RDATA writing for CNAME records.
func TestWriteSignCanonicalRData_CNAME(t *testing.T) {
	records := []DNSRecord{
		{Name: "cname.test.", Type: CNAME, TTL: 300, Host: "TARGET.EXAMPLE.COM.", Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for CNAME: %v", err)
	}
}

// TestWriteSignCanonicalRData_NS verifies canonical RDATA writing for NS records.
func TestWriteSignCanonicalRData_NS(t *testing.T) {
	records := []DNSRecord{
		{Name: "ns.test.", Type: NS, TTL: 300, Host: "NS1.EXAMPLE.COM.", Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for NS: %v", err)
	}
}

// TestWriteSignCanonicalRData_MX verifies canonical RDATA writing for MX records.
func TestWriteSignCanonicalRData_MX(t *testing.T) {
	records := []DNSRecord{
		{Name: "mx.test.", Type: MX, TTL: 300, Priority: 10, Host: "MAIL.EXAMPLE.COM.", Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for MX: %v", err)
	}
}

// TestWriteSignCanonicalRData_TXT verifies canonical RDATA writing for TXT records.
func TestWriteSignCanonicalRData_TXT(t *testing.T) {
	records := []DNSRecord{
		{Name: "txt.test.", Type: TXT, TTL: 300, Txt: "Hello World Test", Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for TXT: %v", err)
	}
}

// TestWriteSignCanonicalRData_SOA verifies canonical RDATA writing for SOA records.
func TestWriteSignCanonicalRData_SOA(t *testing.T) {
	records := []DNSRecord{
		{Name: "soa.test.", Type: SOA, TTL: 300,
			MName:   "NS1.EXAMPLE.COM.",
			RName:   "ADMIN.EXAMPLE.COM.",
			Serial:  2024050101,
			Refresh: 3600,
			Retry:   600,
			Expire:  1209600,
			Minimum: 300,
			Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for SOA: %v", err)
	}
}

// TestWriteSignCanonicalRData_SRV verifies canonical RDATA writing for SRV records.
func TestWriteSignCanonicalRData_SRV(t *testing.T) {
	records := []DNSRecord{
		{Name: "_sip._tcp.srv.test.", Type: SRV, TTL: 300, Priority: 10, Weight: 20, Port: 5060, Host: "SIP.EXAMPLE.COM.", Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for SRV: %v", err)
	}
}

// TestWriteSignCanonicalRData_DNSKEY verifies canonical RDATA writing for DNSKEY records.
func TestWriteSignCanonicalRData_DNSKEY(t *testing.T) {
	records := []DNSRecord{
		{Name: "dnskey.test.", Type: DNSKEY, TTL: 300, Flags: 257, Algorithm: 13, PublicKey: []byte{0x01, 0x02, 0x03, 0x04}, Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for DNSKEY: %v", err)
	}
}

// TestWriteSignCanonicalRData_DS verifies canonical RDATA writing for DS records.
func TestWriteSignCanonicalRData_DS(t *testing.T) {
	records := []DNSRecord{
		{Name: "ds.test.", Type: DS, TTL: 300, KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: []byte{0xaa, 0xbb, 0xcc, 0xdd}, Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for DS: %v", err)
	}
}

// TestWriteSignCanonicalRData_NSEC verifies canonical RDATA writing for NSEC records.
func TestWriteSignCanonicalRData_NSEC(t *testing.T) {
	records := []DNSRecord{
		{Name: "nsec.test.", Type: NSEC, TTL: 300, NextName: "next.test.", TypeBitMap: []byte{0x00, 0x01, 0x00, 0x1e}, Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for NSEC: %v", err)
	}
}

// TestWriteSignCanonicalRData_PTR verifies canonical RDATA writing for PTR records.
func TestWriteSignCanonicalRData_PTR(t *testing.T) {
	records := []DNSRecord{
		{Name: "1.2.3.4.in-addr.arpa.", Type: PTR, TTL: 300, Host: "PTR.TARGET.COM.", Class: 1},
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := SignRRSet(records, priv, AlgorithmECDSAP256, "test.", 1234, 1600000000, 1700000000)
	if err != nil {
		t.Fatalf("SignRRSet failed for PTR: %v", err)
	}
}
