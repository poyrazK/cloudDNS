package packet

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestPacketCoverageAddEDE(t *testing.T) {
	r := DNSRecord{Type: OPT}
	r.AddEDE(15, "Blocked")
	if len(r.Options) != 1 {
		t.Fatalf("Expected 1 option, got %d", len(r.Options))
	}
	if r.Options[0].Code != 15 {
		t.Errorf("Expected option code 15, got %d", r.Options[0].Code)
	}
	if string(r.Options[0].Data) != string([]byte{0, 15, 'B', 'l', 'o', 'c', 'k', 'e', 'd'}) {
		t.Errorf("Option data mismatch")
	}

	r.AddEDE(16, "")
	if string(r.Options[1].Data) != string([]byte{0, 16}) {
		t.Errorf("Option data mismatch without text")
	}
}

func TestPacketCoverageRecordTypeToQueryType(t *testing.T) {
	tests := []struct {
		rt string
		qt QueryType
	}{
		{"A", A},
		{"AAAA", AAAA},
		{"CNAME", CNAME},
		{"NS", NS},
		{"MX", MX},
		{"SOA", SOA},
		{"TXT", TXT},
		{"SRV", SRV},
		{"PTR", PTR},
		{"DS", UNKNOWN},
		{"DNSKEY", UNKNOWN},
		{"RRSIG", UNKNOWN},
		{"NSEC", UNKNOWN},
		{"NSEC3", UNKNOWN},
		{"UNKNOWN_STRING_A", UNKNOWN},
	}
	for _, tt := range tests {
		got := RecordTypeToQueryType(domain.RecordType(tt.rt))
		if got != tt.qt {
			t.Errorf("RecordTypeToQueryType(%s) = %v; want %v", tt.rt, got, tt.qt)
		}
	}
}

func TestPacketCoverageString(t *testing.T) {
	if A.String() != "A" {
		t.Error("A.String() failed")
	}
	if QueryType(999).String() != "TYPE999" {
		t.Error("Unknown type String() failed")
	}
}

func TestPacketCoverageNewDNSPacket(t *testing.T) {
	p := NewDNSPacket()
	if p.Header.ID != 0 || len(p.Questions) != 0 {
		t.Error("NewDNSPacket initialization failed")
	}
}

func TestPacketCoverageDNSHeaderWriteRead(t *testing.T) {
	h := NewDNSHeader()
	h.ID = 1234
	h.RecursionDesired = true
	h.TruncatedMessage = true
	h.AuthoritativeAnswer = true
	h.Opcode = 5
	h.Response = true
	h.ResCode = 3
	h.CheckingDisabled = true
	h.AuthedData = true
	h.Z = true
	h.RecursionAvailable = true
	h.Questions = 1
	h.Answers = 2
	h.AuthoritativeEntries = 3
	h.ResourceEntries = 4

	buf := NewBytePacketBuffer()
	if err := h.Write(buf); err != nil {
		t.Fatalf("DNSHeader.Write failed: %v", err)
	}

	_ = buf.Seek(0)
	h2 := NewDNSHeader()
	if err := h2.Read(buf); err != nil {
		t.Fatalf("DNSHeader.Read failed: %v", err)
	}

	if h.ID != h2.ID || h.Opcode != h2.Opcode || h.RecursionDesired != h2.RecursionDesired ||
		h.Questions != h2.Questions || h.Answers != h2.Answers {
		t.Errorf("DNSHeader write/read mismatch: %+v != %+v", h, h2)
	}
}

const testComDomain = "test.com."

func TestPacketCoverageNewDNSQuestion(t *testing.T) {
	q := NewDNSQuestion(testComDomain, AAAA)
	if q.Name != testComDomain || q.QType != AAAA || q.QClass != 1 {
		t.Error("NewDNSQuestion initialization failed")
	}
}

func TestPacketCoverageDNSQuestionWriteRead(t *testing.T) {
	q := NewDNSQuestion(testComDomain, MX)
	buf := NewBytePacketBuffer()
	if err := q.Write(buf); err != nil {
		t.Fatalf("DNSQuestion.Write failed: %v", err)
	}

	_ = buf.Seek(0)
	q2 := DNSQuestion{}
	if err := q2.Read(buf); err != nil {
		t.Fatalf("DNSQuestion.Read failed: %v", err)
	}

	if q.Name != q2.Name || q.QType != q2.QType || q.QClass != q2.QClass {
		t.Errorf("DNSQuestion write/read mismatch")
	}
}

func TestPacketCoverageDNSPacketFromBuffer(t *testing.T) {
	p := NewDNSPacket()
	p.Header.ID = 1111
	p.Header.Questions = 1
	p.Header.Answers = 1
	p.Questions = append(p.Questions, *NewDNSQuestion("a.test.", A))
	p.Answers = append(p.Answers, DNSRecord{Name: "a.test.", Type: A, Class: 1, TTL: 60, IP: net.ParseIP("1.1.1.1")})

	buf := NewBytePacketBuffer()
	if err := p.Write(buf); err != nil {
		t.Fatalf("DNSPacket.Write failed: %v", err)
	}

	_ = buf.Seek(0)
	p2 := NewDNSPacket()
	if err := p2.FromBuffer(buf); err != nil {
		t.Fatalf("DNSPacket.FromBuffer failed: %v", err)
	}

	if p2.Header.ID != 1111 || len(p2.Questions) != 1 || len(p2.Answers) != 1 {
		t.Errorf("DNSPacket FromBuffer mismatch")
	}
}

func TestPacketCoverageBufferExtra(t *testing.T) {
	b := GetBuffer()
	defer PutBuffer(b)

	b.Load([]byte{1, 2, 3})
	if b.Position() != 0 || b.Len != 3 {
		t.Errorf("Load mismatch")
	}

	if err := b.Seek(1); err != nil {
		t.Errorf("Seek failed: %v", err)
	}

	if _, err := b.ReadRange(0, 2); err != nil {
		t.Errorf("ReadRange failed: %v", err)
	}

	if _, err := b.GetRange(1, 2); err != nil {
		t.Errorf("GetRange failed: %v", err)
	}

	if err := b.WriteRange(1, []byte{9, 9}); err != nil {
		t.Errorf("WriteRange failed: %v", err)
	}

	if string(b.Buf[:3]) != string([]byte{1, 9, 9}) {
		t.Errorf("WriteRange content mismatch: %v", b.Buf[:3])
	}
}
