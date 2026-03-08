package packet

import (
	"encoding/hex"
	"net"
	"reflect"
	"strings"
	"testing"
)

// Helper to decode hex string and ignore whitespace/newlines for readability
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}
	return b
}

func TestRFC1035_StandardQuery(t *testing.T) {
	// A standard query for "example.com." Type A, Class IN
	// ID: 0x1234, Flags: 0x0100 (Standard query, RD=1)
	// QD: 1, AN: 0, NS: 0, AR: 0
	// Question: \x07example\x03com\x00, Type: 0x0001, Class: 0x0001
	hexStr := `
		12 34 01 00
		00 01 00 00
		00 00 00 00
		07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
		00 01 00 01
	`
	data := decodeHex(t, hexStr)

	buf := NewBytePacketBuffer()
	buf.Load(data)

	pkt := NewDNSPacket()
	err := pkt.FromBuffer(buf)
	if err != nil {
		t.Fatalf("Failed to parse RFC 1035 standard query: %v", err)
	}

	if pkt.Header.ID != 0x1234 {
		t.Errorf("Expected ID 0x1234, got 0x%04x", pkt.Header.ID)
	}
	if pkt.Header.Opcode != OpcodeQuery {
		t.Errorf("Expected OpcodeQuery (0), got %d", pkt.Header.Opcode)
	}
	if pkt.Header.RecursionDesired != true {
		t.Errorf("Expected RecursionDesired to be true")
	}
	if len(pkt.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(pkt.Questions))
	}

	q := pkt.Questions[0]
	if q.Name != "example.com." {
		t.Errorf("Expected name 'example.com.', got '%s'", q.Name)
	}
	if q.QType != A {
		t.Errorf("Expected type A (1), got %d", q.QType)
	}
	if q.QClass != 1 {
		t.Errorf("Expected class IN (1), got %d", q.QClass)
	}

	// Round-trip verification
	writeBuf := NewBytePacketBuffer()
	err = pkt.Write(writeBuf)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}
	writtenData := writeBuf.Buf[:writeBuf.Position()]
	if !reflect.DeepEqual(data, writtenData) {
		t.Errorf("Round-trip failed.\nExpected: %x\nGot:      %x", data, writtenData)
	}
}

func TestRFC1035_PointerCompression(t *testing.T) {
	// A response utilizing pointer compression for "example.com."
	// Question: example.com.
	// Answer 1: example.com. A 192.0.2.1
	// Answer 2: ns.example.com. A 192.0.2.2 (ns points back to example.com.)
	hexStr := `
		ab cd 81 80
		00 01 00 02
		00 00 00 00
		07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
		00 01 00 01
		c0 0c
		00 01 00 01 00 00 0e 10 00 04
		c0 00 02 01
		02 6e 73 c0 0c
		00 01 00 01 00 00 0e 10 00 04
		c0 00 02 02
	`
	data := decodeHex(t, hexStr)

	buf := NewBytePacketBuffer()
	buf.Load(data)

	pkt := NewDNSPacket()
	err := pkt.FromBuffer(buf)
	if err != nil {
		t.Fatalf("Failed to parse pointer compression packet: %v", err)
	}

	if len(pkt.Questions) != 1 || pkt.Questions[0].Name != "example.com." {
		t.Fatalf("Failed to parse question: %+v", pkt.Questions)
	}

	if len(pkt.Answers) != 2 {
		t.Fatalf("Expected 2 answers, got %d", len(pkt.Answers))
	}

	a1 := pkt.Answers[0]
	if a1.Name != "example.com." {
		t.Errorf("Answer 1 name mismatch: got %s", a1.Name)
	}
	if !a1.IP.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("Answer 1 IP mismatch: got %v", a1.IP)
	}

	a2 := pkt.Answers[1]
	if a2.Name != "ns.example.com." {
		t.Errorf("Answer 2 name mismatch (decompression failed): got %s", a2.Name)
	}
	if !a2.IP.Equal(net.ParseIP("192.0.2.2")) {
		t.Errorf("Answer 2 IP mismatch: got %v", a2.IP)
	}
}

func TestRFC6891_EDNS0(t *testing.T) {
	// A query with an OPT pseudo-RR in the Additional section
	// Requesting payload size 4096, DO bit set.
	hexStr := `
		11 22 01 00
		00 01 00 00
		00 00 00 01
		07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
		00 01 00 01
		00
		00 29 10 00 00 00 80 00 00 00
	`
	data := decodeHex(t, hexStr)

	buf := NewBytePacketBuffer()
	buf.Load(data)

	pkt := NewDNSPacket()
	err := pkt.FromBuffer(buf)
	if err != nil {
		t.Fatalf("Failed to parse EDNS0 packet: %v", err)
	}

	if len(pkt.Resources) != 1 {
		t.Fatalf("Expected 1 resource record (OPT), got %d", len(pkt.Resources))
	}

	opt := pkt.Resources[0]
	if opt.Type != OPT {
		t.Fatalf("Expected OPT record type, got %d", opt.Type)
	}

	// Payload size is stored in the Class field for OPT records
	if opt.Class != 4096 {
		t.Errorf("Expected payload size 4096, got %d", opt.Class)
	}

	// DO bit is the highest bit in the extended RCODE / flags TTL field
	if opt.TTL&0x8000 == 0 {
		t.Errorf("Expected DO bit to be set")
	}
}

func TestRFC4034_DNSSEC_RRSIG(t *testing.T) {
	// Parsing an RRSIG record
	// Example format: example.com. 3600 IN RRSIG A 8 2 3600 20260307 20260207 1234 example.com. [signature]
	hexStr := `
		12 34 81 80
		00 01 00 01
		00 00 00 00
		07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
		00 01 00 01
		07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
		00 2e 00 01
		00 00 0e 10
		00 23
		00 01 08 02 00 00 0e 10
		78 c9 12 34 78 a0 aa bb
		12 34 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00
		aa bb cc dd
	`
	data := decodeHex(t, hexStr)

	buf := NewBytePacketBuffer()
	buf.Load(data)

	pkt := NewDNSPacket()
	err := pkt.FromBuffer(buf)
	if err != nil {
		t.Fatalf("Failed to parse DNSSEC RRSIG packet: %v", err)
	}

	if len(pkt.Answers) != 1 {
		t.Fatalf("Expected 1 RRSIG answer, got %d", len(pkt.Answers))
	}

	sig := pkt.Answers[0]
	if sig.Type != RRSIG {
		t.Fatalf("Expected RRSIG record, got %d", sig.Type)
	}

	if sig.TypeCovered != uint16(A) {
		t.Errorf("Expected TypeCovered A (1), got %d", sig.TypeCovered)
	}
	if sig.Algorithm != 8 {
		t.Errorf("Expected Algorithm 8, got %d", sig.Algorithm)
	}
	if sig.Labels != 2 {
		t.Errorf("Expected 2 labels, got %d", sig.Labels)
	}
	if sig.OrigTTL != 3600 {
		t.Errorf("Expected OrigTTL 3600, got %d", sig.OrigTTL)
	}
	if sig.KeyTag != 0x1234 {
		t.Errorf("Expected KeyTag 0x1234, got %d", sig.KeyTag)
	}
	if sig.SignerName != "example.com." {
		t.Errorf("Expected SignerName 'example.com.', got '%s'", sig.SignerName)
	}
	if !reflect.DeepEqual(sig.Signature, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Errorf("Signature mismatch")
	}
}
