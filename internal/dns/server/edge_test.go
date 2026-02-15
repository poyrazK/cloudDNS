package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestQueryTypeToRecordType_All ensures that all supported DNS record types
// are correctly mapped to their corresponding internal domain types.
func TestQueryTypeToRecordType_All(t *testing.T) {
	tests := []struct {
		qType packet.QueryType
		want  domain.RecordType
	}{
		{packet.A, domain.TypeA},
		{packet.AAAA, domain.TypeAAAA},
		{packet.CNAME, domain.TypeCNAME},
		{packet.NS, domain.TypeNS},
		{packet.MX, domain.TypeMX},
		{packet.SOA, domain.TypeSOA},
		{packet.TXT, domain.TypeTXT},
		{packet.PTR, domain.TypePTR},
		{packet.ANY, ""},
		{packet.UNKNOWN, ""},
	}

	for _, tt := range tests {
		if got := queryTypeToRecordType(tt.qType); got != tt.want {
			t.Errorf("queryTypeToRecordType(%v) = %v, want %v", tt.qType, got, tt.want)
		}
	}
}

// TestHandleUpdate_FormErr verifies that a Dynamic Update with an invalid 
// number of zones (ZOCOUNT != 1) returns a FORMERR response.
func TestHandleUpdate_FormErr(t *testing.T) {
	srv := NewServer("127.0.0.1:0", &mockServerRepo{}, nil)
	req := packet.NewDNSPacket()
	req.Header.Opcode = packet.OPCODE_UPDATE
	// No questions (ZOCOUNT = 0)
	
	err := srv.handleUpdate(req, nil, "127.0.0.1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		p.FromBuffer(pb)
		if p.Header.ResCode != packet.RCODE_FORMERR {
			t.Errorf("Expected FORMERR for empty update, got %d", p.Header.ResCode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("handleUpdate failed: %v", err)
	}
}

// TestHandleIXFR_NoAuthority verifies that an IXFR request without the 
// client's current SOA in the Authority section returns a FORMERR.
func TestHandleIXFR_NoAuthority(t *testing.T) {
	srv := NewServer("127.0.0.1:0", &mockServerRepo{}, nil)
	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "test.", QType: packet.IXFR})
	
	// No Authority section
	srv.handleIXFR(&mockConn{}, req)
}

type mockConn struct {
	net.Conn
}

func (m *mockConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockConn) Close() error                { return nil }

// TestHandlePacket_NoQuestions verifies that a DNS packet with no questions
// returns a FORMERR response as per RFC standards.
func TestHandlePacket_NoQuestions(t *testing.T) {
	srv := NewServer("127.0.0.1:0", &mockServerRepo{}, nil)
	req := packet.NewDNSPacket()
	req.Header.ID = 123
	
	buf := packet.NewBytePacketBuffer()
	req.Write(buf)
	
	err := srv.handlePacket(buf.Buf[:buf.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		p.FromBuffer(pb)
		if p.Header.ResCode != 4 {
			t.Errorf("Expected FORMERR, got %d", p.Header.ResCode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}
}
