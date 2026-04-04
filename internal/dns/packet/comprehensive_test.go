package packet

import (
	"testing"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
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

func TestQueryType_String_Comprehensive(t *testing.T) {
	tests := []struct {
		typ QueryType
		want string
	}{
		{A, "A"}, {NS, "NS"}, {CNAME, "CNAME"}, {SOA, "SOA"},
		{MX, "MX"}, {TXT, "TXT"}, {AAAA, "AAAA"}, {SRV, "SRV"},
		{DS, "DS"}, {RRSIG, "RRSIG"}, {NSEC, "NSEC"}, {DNSKEY, "DNSKEY"},
		{NSEC3, "NSEC3"}, {NSEC3PARAM, "NSEC3PARAM"}, {AXFR, "AXFR"},
		{IXFR, "IXFR"}, {ANY, "ANY"}, {OPT, "OPT"}, {TSIG, "TSIG"},
		{PTR, "PTR"}, {CAA, "CAA"}, {QueryType(65535), "TYPE65535"},
	}
	for _, tt := range tests {
		if got := tt.typ.String(); got != tt.want {
			t.Errorf("QueryType(%d).String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestRecordTypeToQueryType_Comprehensive(t *testing.T) {
	tests := []struct {
		typ domain.RecordType
		want QueryType
	}{
		{domain.TypeA, A}, {domain.TypeNS, NS}, {domain.TypeCNAME, CNAME},
		{domain.TypeSOA, SOA}, {domain.TypeMX, MX}, {domain.TypeTXT, TXT},
		{domain.TypeAAAA, AAAA}, {domain.TypePTR, PTR}, {domain.TypeSRV, SRV},
		{domain.TypeCAA, CAA}, {domain.RecordType("UNKNOWN"), UNKNOWN},
	}
	for _, tt := range tests {
		if got := RecordTypeToQueryType(tt.typ); got != tt.want {
			t.Errorf("RecordTypeToQueryType(%q) = %v, want %v", tt.typ, got, tt.want)
		}
	}
}
