package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestHandleIXFR_UpToDate(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", Name: "example.test."},
		},
		records: []domain.Record{
			{ID: "soa-1", ZoneID: "zone-1", Name: "example.test.", Type: domain.TypeSOA, Content: "ns1.example.test. hostmaster.example.test. 100 3600 600 604800 300"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 123
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.test.", QType: packet.IXFR})
	// Client SOA with serial 100
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "example.test.",
		Type: packet.SOA,
		Serial: 100,
	})

	buffer := packet.NewBytePacketBuffer()
	req.Write(buffer)

	// IXFR requires TCP
	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	// Verify response: should just be the SOA
	if len(conn.captured) != 1 {
		t.Fatalf("Expected 1 response packet, got %d", len(conn.captured))
	}
	
	resp := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(conn.captured[0])
	resp.FromBuffer(pBuf)

	if len(resp.Answers) != 1 || resp.Answers[0].Type != packet.SOA {
		t.Errorf("Expected single SOA response")
	}
	if resp.Answers[0].Serial != 100 {
		t.Errorf("Expected serial 100, got %d", resp.Answers[0].Serial)
	}
}

func TestHandleIXFR_WithChanges(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "zone-1", Name: "example.test."},
		},
		records: []domain.Record{
			{ID: "soa-1", ZoneID: "zone-1", Name: "example.test.", Type: domain.TypeSOA, Content: "ns1.example.test. hostmaster.example.test. 101 3600 600 604800 300"},
		},
	}
	// Add history: Client has 100, we are at 101
	repo.RecordZoneChange(nil, &domain.ZoneChange{
		ZoneID: "zone-1", Serial: 101, Action: "ADD", Name: "new.example.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300,
	})

	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 456
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "example.test.",
		Type: packet.SOA,
		Serial: 100,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	// Sequence: [Current SOA] -> [Old SOA, Deletions] -> [New SOA, Additions] -> [Current SOA]
	// Our stub implementation sends 4 responses for a single version increment
	if len(conn.captured) < 3 {
		t.Fatalf("Expected multiple response packets for IXFR, got %d", len(conn.captured))
	}

	// First packet should be current SOA
	resp1 := packet.NewDNSPacket()
	pBuf1 := packet.NewBytePacketBuffer()
	pBuf1.Load(conn.captured[0])
	resp1.FromBuffer(pBuf1)
	if resp1.Answers[0].Serial != 101 {
		t.Errorf("First packet should be current SOA (101), got %d", resp1.Answers[0].Serial)
	}
}

type mockTCPConn struct {
	net.Conn
	captured [][]byte
}

func (m *mockTCPConn) Write(b []byte) (int, error) {
	// TCP DNS prefixes with 2 bytes length
	if len(b) > 2 {
		m.captured = append(m.captured, b[2:])
	}
	return len(b), nil
}
func (m *mockTCPConn) Close() error { return nil }
func (m *mockTCPConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345} }
