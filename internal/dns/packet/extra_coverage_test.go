package packet

import (
	"net"
	"testing"
	"time"
)

func TestDNSRecord_Write_ANY_NONE(t *testing.T) {
	// RFC 2136 Section 2.5.2: Class ANY (255) means "Delete an RRset"
	// RDLENGTH MUST be 0.
	recAny := DNSRecord{
		Name:  "test.com.",
		Type:  A,
		Class: 255,
		TTL:   0,
	}
	buf := NewBytePacketBuffer()
	_, err := recAny.Write(buf)
	if err != nil {
		t.Fatalf("Failed to write Class ANY record: %v", err)
	}
	
	// Check RDLENGTH at pos (name + type + class + ttl)
	// name "test.com." is [4]test[3]com[0] = 10 bytes
	// type (2), class (2), ttl (4) = 8 bytes
	// total 18 bytes. RDLENGTH is at pos 18.
	rdLen, _ := buf.GetRange(18, 2)
	if rdLen[0] != 0 || rdLen[1] != 0 {
		t.Errorf("Expected RDLENGTH 0 for Class ANY, got %v", rdLen)
	}

	// Case: NONE (254) with empty data
	recNone := DNSRecord{
		Name:  "test.com.",
		Type:  999, // Unknown type to hit default path
		Class: 254,
		TTL:   0,
		Data:  []byte{},
	}
	buf.Reset()
	_, err = recNone.Write(buf)
	if err != nil {
		t.Fatalf("Failed to write Class NONE record: %v", err)
	}
	rdLen, _ = buf.GetRange(18, 2)
	if rdLen[0] != 0 || rdLen[1] != 0 {
		t.Errorf("Expected RDLENGTH 0 for Class NONE with no data, got %v", rdLen)
	}
}

func TestDNSRecord_Read_OPT_Extended(t *testing.T) {
	// Write an OPT record with multiple options
	rec := DNSRecord{
		Name:           ".",
		Type:           OPT,
		UDPPayloadSize: 4096,
		ExtendedRcode:  1,
		EDNSVersion:    0,
		Z:              0,
		Options: []EdnsOption{
			{Code: 8, Data: []byte{1, 2, 3, 4}}, // ECS or something
			{Code: 10, Data: []byte{5, 6}},      // Cookie
		},
	}
	buf := NewBytePacketBuffer()
	_, _ = rec.Write(buf)
	
	_ = buf.Seek(0)
	var parsed DNSRecord
	err := parsed.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read complex OPT record: %v", err)
	}
	
	if len(parsed.Options) != 2 {
		t.Errorf("Expected 2 options, got %d", len(parsed.Options))
	}
}

func TestDNSRecord_Read_DefaultPath(t *testing.T) {
	// Test reading an unknown type that should just be skipped via DataLen
	buf := NewBytePacketBuffer()
	_ = buf.Write(0) // Name .
	_ = buf.Writeu16(999) // Unknown Type
	_ = buf.Writeu16(1) // Class IN
	_ = buf.Writeu32(60) // TTL
	_ = buf.Writeu16(4) // RDLENGTH
	_ = buf.Writeu32(0xDEADBEEF) // Data
	
	buf.Len = buf.Pos
	_ = buf.Seek(0)
	
	var parsed DNSRecord
	err := parsed.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read unknown record type: %v", err)
	}
	
	if buf.Position() != buf.Len {
		t.Errorf("Expected buffer to be advanced by RDLENGTH")
	}
}

func TestDNSPacket_Write_ErrorPaths(t *testing.T) {
	p := NewDNSPacket()
	p.Questions = append(p.Questions, DNSQuestion{Name: "q.", QType: A})
	p.Answers = append(p.Answers, DNSRecord{Name: "a.", Type: A, IP: net.ParseIP("1.1.1.1")})
	
	buf := NewBytePacketBuffer()
	
	// 1. Fail at Header
	buf.Pos = MaxPacketSize
	if err := p.Write(buf); err == nil {
		t.Errorf("Expected error writing packet at end of buffer (Header)")
	}
	
	// 2. Fail at Questions
	buf.Reset()
	// Let's try to trigger error in Questions write by moving Pos to near end
	buf.Pos = MaxPacketSize - 2
	if err := p.Write(buf); err == nil {
		t.Errorf("Expected error writing packet at end of buffer (Questions)")
	}
}

func TestDNSRecord_Write_TSIG_Complex(t *testing.T) {
	rec := DNSRecord{
		Name:          "tsig.",
		Type:          TSIG,
		Class:         255,
		TTL:           0,
		AlgorithmName: "hmac-sha256.",
		TimeSigned:    1234567890,
		Fudge:         300,
		MAC:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
		OriginalID:    1234,
		Error:         0,
		Other:         []byte{9, 10},
	}
	
	buf := NewBytePacketBuffer()
	_, err := rec.Write(buf)
	if err != nil {
		t.Fatalf("Failed to write TSIG record: %v", err)
	}
	
	_ = buf.Seek(0)
	var parsed DNSRecord
	err = parsed.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read TSIG record: %v", err)
	}
	
	if parsed.TimeSigned != rec.TimeSigned || len(parsed.MAC) != len(rec.MAC) {
		t.Errorf("TSIG field mismatch")
	}
}

func TestTSIG_TimeDrift_Future(t *testing.T) {
	p := NewDNSPacket()
	secret := []byte("secret")
	tsig := DNSRecord{
		Name:          "key.",
		Type:          TSIG,
		Class:         255,
		AlgorithmName: "hmac-md5.sig-alg.reg.int.",
		TimeSigned:    uint64(time.Now().Add(10 * time.Minute).Unix()), // Future
		Fudge:         300,
		MAC:           []byte{1, 2, 3},
	}
	p.Resources = append(p.Resources, tsig)
	
	buf := NewBytePacketBuffer()
	_ = p.Write(buf)
	
	err := p.VerifyTSIG(buf.Buf, 0, secret)
	if err == nil || err.Error() != "TSIG time drift exceeded" {
		t.Errorf("Expected drift error for future time, got %v", err)
	}
}

func TestBytePacketBuffer_ClearMaps(t *testing.T) {
	buf := NewBytePacketBuffer()
	buf.HasNames = true
	_ = buf.WriteName("test.com.")
	
	if len(buf.names) == 0 {
		t.Errorf("Expected names map to be populated")
	}
	
	buf.Reset()
	if len(buf.names) != 0 {
		t.Errorf("Expected names map to be cleared after Reset")
	}
	
	_ = buf.WriteName("test.com.")
	buf.Load([]byte{0})
	if len(buf.names) != 0 {
		t.Errorf("Expected names map to be cleared after Load")
	}
}

func TestDNSSEC_CountLabels_Root(t *testing.T) {
	if countLabels(".") != 0 {
		t.Errorf("Expected 0 labels for root")
	}
	if countLabels("") != 0 {
		t.Errorf("Expected 0 labels for empty string")
	}
}

func TestDNSSEC_ComputeDS_SHA1(t *testing.T) {
	keyRec := DNSRecord{
		Name: "test.", Type: DNSKEY, Class: 1, 
		Flags: 256, Algorithm: 13, PublicKey: []byte{1, 2, 3, 4},
	}
	ds, err := keyRec.ComputeDS(1) // SHA-1
	if err != nil {
		t.Fatalf("ComputeDS SHA-1 failed: %v", err)
	}
	if ds.DigestType != 1 || len(ds.Digest) != 20 {
		t.Errorf("Invalid SHA-1 digest")
	}
}
