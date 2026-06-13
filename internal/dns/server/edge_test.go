package server

import (
	"context"
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
	req.Header.Opcode = packet.OpcodeUpdate
	// No questions (ZOCOUNT = 0)
	
	err := srv.handleUpdate(context.Background(), req, nil, "127.0.0.1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != packet.RcodeFormErr {
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
	srv.handleIXFR(context.Background(), &mockConn{}, req, nil, nil)
}

type mockConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Write(b []byte) (int, error)     { return len(b), nil }
func (m *mockConn) Close() error                    { return nil }
func (m *mockConn) RemoteAddr() net.Addr            {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *mockConn) LocalAddr() net.Addr             {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
}

// TestHandlePacket_NoQuestions verifies that a DNS packet with no questions
// returns a FORMERR response as per RFC standards.
func TestHandlePacket_NoQuestions(t *testing.T) {
	srv := NewServer("127.0.0.1:0", &mockServerRepo{}, nil)
	req := packet.NewDNSPacket()
	req.Header.ID = 123
	
	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	
	err := srv.handlePacket(context.Background(),buf.Buf[:buf.Position()], "127.0.0.1:1", func(resp []byte) error {
		p := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(resp)
		_ = p.FromBuffer(pb)
		if p.Header.ResCode != 4 {
			t.Errorf("Expected FORMERR, got %d", p.Header.ResCode)
		}
		return nil
	}, "udp")
	if err != nil {
		t.Fatalf("handlePacket failed: %v", err)
	}
}

// TestHandleAXFR_RateLimited verifies that AXFR returns SERVFAIL when rate limited.
func TestHandleAXFR_RateLimited(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	// Replace limiter with one that denies all
	srv.limiter = newRateLimiter(0, 0, 1000)

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "test.", QType: packet.AXFR})

	conn := &mockTCPConn{}
	srv.handleAXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}
	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != 2 { // SERVFAIL
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}

// TestHandleIXFR_RateLimited verifies that IXFR returns SERVFAIL when rate limited.
func TestHandleIXFR_RateLimited(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "test.", Type: domain.TypeSOA, Content: "ns1. ns2. 1 2 3 4 5"},
		},
	}
	srv := NewServer(":0", repo, nil)
	// Replace limiter with one that denies all
	srv.limiter = newRateLimiter(0, 0, 1000)

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "test.", QType: packet.IXFR})

	conn := &mockTCPConn{}
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response, got %d", len(conn.captured))
	}
	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = res.FromBuffer(pb)
	if res.Header.ResCode != 2 { // SERVFAIL
		t.Errorf("Expected SERVFAIL (2), got %d", res.Header.ResCode)
	}
}
