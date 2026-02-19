package packet

import (
	"testing"
)

func TestDNSQuestion_ReadWrite_Comprehensive(t *testing.T) {
	q := DNSQuestion{
		Name:  "example.com.",
		QType: AAAA,
	}
	buf := NewBytePacketBuffer()
	err := q.Write(buf)
	if err != nil {
		t.Fatalf("Question.Write failed: %v", err)
	}

	_ = buf.Seek(0)
	var q2 DNSQuestion
	err = q2.Read(buf)
	if err != nil {
		t.Fatalf("Question.Read failed: %v", err)
	}

	if q2.Name != q.Name || q2.QType != q.QType {
		t.Errorf("Question mismatch: %+v vs %+v", q2, q)
	}
}

func TestDNSRecord_Read_SkippedTypes(t *testing.T) {
	types := []QueryType{AXFR, IXFR, ANY}
	for _, typ := range types {
		buf := NewBytePacketBuffer()
		_ = buf.Write(0) // .
		_ = buf.Writeu16(uint16(typ))
		_ = buf.Writeu16(1) // Class
		_ = buf.Writeu32(0) // TTL
		_ = buf.Writeu16(4) // Len
		_ = buf.Writeu32(0) // Data
		
		buf.Len = buf.Pos
		_ = buf.Seek(0)
		var r DNSRecord
		err := r.Read(buf)
		if err != nil {
			t.Errorf("Failed to read skipped type %v: %v", typ, err)
		}
	}
}

func TestDNSHeader_Flags_Comprehensive(t *testing.T) {
	h := DNSHeader{
		ID:               0x1234,
		Response:         true,
		Opcode:           OpcodeUpdate,
		AuthoritativeAnswer: true,
		TruncatedMessage: true,
		RecursionDesired: true,
		RecursionAvailable: true,
		Z:                true,
		AuthedData:       true,
		CheckingDisabled: true,
		ResCode:          RcodeRefused,
		Questions:        1,
		Answers:          2,
		AuthoritativeEntries: 3,
		ResourceEntries: 4,
	}
	
	buf := NewBytePacketBuffer()
	_ = h.Write(buf)
	
	_ = buf.Seek(0)
	var h2 DNSHeader
	_ = h2.Read(buf)
	
	if h2.Response != h.Response || h2.Opcode != h.Opcode || h2.ResCode != h.ResCode {
		t.Errorf("Header flag mismatch: %+v vs %+v", h2, h)
	}
	if h2.Questions != 1 || h2.Answers != 2 || h2.AuthoritativeEntries != 3 || h2.ResourceEntries != 4 {
		t.Errorf("Header count mismatch")
	}
}

func TestDNSRecord_AddEDE_Comprehensive(t *testing.T) {
	r := &DNSRecord{}
	r.AddEDE(EdeSignatureExpired, "expired")
	if len(r.Options) != 1 || r.Options[0].Code != 15 {
		t.Errorf("AddEDE failed")
	}
}
