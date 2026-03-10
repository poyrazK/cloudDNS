package server

import (
	"context"
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
		Name:   "example.test.",
		Type:   packet.SOA,
		Serial: 100,
	})

	buffer := packet.NewBytePacketBuffer()
	_ = req.Write(buffer)

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
	_ = resp.FromBuffer(pBuf)

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
	_ = repo.RecordZoneChange(context.Background(), &domain.ZoneChange{
		ZoneID: "zone-1", Serial: 101, Action: "ADD", Name: "new.example.test.", Type: "A", Content: "1.2.3.4", TTL: 300,
	})

	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 456
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "example.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name:   "example.test.",
		Type:   packet.SOA,
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
	_ = resp1.FromBuffer(pBuf1)
	if resp1.Answers[0].Serial != 101 {
		t.Errorf("First packet should be current SOA (101), got %d", resp1.Answers[0].Serial)
	}
}

func TestHandleIXFR_MissingSOA(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "nosoa.test."}},
		// No records
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "nosoa.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "nosoa.test.", Type: packet.SOA, Class: 1, Serial: 50,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL, got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_NoAuthoritySOA(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "noauth.test."}},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "noauth.test.", QType: packet.IXFR})
	// Missing SOA in Authority Section

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeFormErr {
		t.Errorf("Expected FORMERR (1), got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_ZoneNotFound(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "nonexistent.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "nonexistent.test.", Type: packet.SOA, Class: 1, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeNxDomain {
		t.Errorf("Expected NXDOMAIN (3), got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_MalformedSOAContent(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "malformed.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "malformed.test.", Type: domain.TypeSOA, Content: "ns1. ns2."}, // Missing serial
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "malformed.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "malformed.test.", Type: packet.SOA, Class: 1, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL for malformed SOA, got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_InvalidSOASerial(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "invalid.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "invalid.test.", Type: domain.TypeSOA, Content: "ns1. ns2. not-a-number 3600 600 604800 300"},
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "invalid.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "invalid.test.", Type: packet.SOA, Class: 1, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL for invalid serial, got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_GapInHistoryFallback(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "gap.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "gap.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 10 3600 600 604800 300"},
			{ZoneID: "z1", Name: "www.gap.test.", Type: domain.TypeA, Content: "1.1.1.1"},
			{ZoneID: "z1", Name: "new.gap.test.", Type: domain.TypeA, Content: "2.2.2.2"},
		},
	}
	// Client has serial 1. Current is 10. History only has 10. Gap detected.
	_ = repo.RecordZoneChange(context.Background(), &domain.ZoneChange{
		ZoneID: "z1", Serial: 10, Action: "ADD", Name: "new.gap.test.", Type: "A", Content: "2.2.2.2",
	})

	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "gap.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "gap.test.", Type: packet.SOA, Class: 1, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	// Should fallback to AXFR. AXFR sequence: SOA, then all records, then SOA.
	// records: SOA, www.gap.test., new.gap.test.
	// Expected responses:
	// 1. Current SOA
	// 2. www.gap.test. (A)
	// 3. new.gap.test. (A)
	// 4. Current SOA (end)
	if len(conn.captured) != 4 {
		t.Fatalf("Expected 4 responses for AXFR fallback, got %d", len(conn.captured))
	}

	// Verify first record is SOA with serial 10
	resp1 := packet.NewDNSPacket()
	pBuf1 := packet.NewBytePacketBuffer()
	pBuf1.Load(conn.captured[0])
	_ = resp1.FromBuffer(pBuf1)
	if resp1.Answers[0].Type != packet.SOA || resp1.Answers[0].Serial != 10 {
		t.Errorf("Expected first response to be SOA with serial 10")
	}

	// Verify last record is SOA with serial 10
	resp4 := packet.NewDNSPacket()
	pBuf4 := packet.NewBytePacketBuffer()
	pBuf4.Load(conn.captured[3])
	_ = resp4.FromBuffer(pBuf4)
	if resp4.Answers[0].Type != packet.SOA || resp4.Answers[0].Serial != 10 {
		t.Errorf("Expected last response to be SOA with serial 10")
	}

	// Verify middle records
	names := []string{resp1.Answers[0].Name, "", "", resp4.Answers[0].Name}
	for i := 1; i < 3; i++ {
		resp := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(conn.captured[i])
		_ = resp.FromBuffer(pb)
		names[i] = resp.Answers[0].Name
	}

	foundWWW := false
	foundNew := false
	for i := 1; i < 3; i++ {
		if names[i] == "www.gap.test." {
			foundWWW = true
		}
		if names[i] == "new.gap.test." {
			foundNew = true
		}
	}
	if !foundWWW || !foundNew {
		t.Errorf("Missing zone records in AXFR fallback: www=%v, new=%v", foundWWW, foundNew)
	}
}

func TestHandleIXFR_ListRecordsError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "listerror.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "listerror.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 10 3600 600 604800 300"},
		},
		failListRecords: true, // Trigger failure during AXFR fallback
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "listerror.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "listerror.test.", Type: packet.SOA, Class: 1, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL for list records failure, got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_MalformedSOA(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "malformed.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "malformed.test.", Type: domain.TypeSOA, Content: "short soa"},
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "malformed.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "malformed.test.", Type: packet.SOA, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) != 1 {
		t.Fatalf("expected 1 TCP response for malformed SOA, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeServFail {
		t.Errorf("Expected SERVFAIL (2), got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_InvalidSerial(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "badserial.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "badserial.test.", Type: domain.TypeSOA, Content: "ns1. ns2. not-a-number 3600 600"},
		},
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "badserial.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "badserial.test.", Type: packet.SOA, Serial: 1,
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) == 0 {
		t.Fatalf("Expected SERVFAIL response for invalid SOA serial, got no response")
	}
}

func TestHandleIXFR_FallbackListError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "fallbackerr.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "fallbackerr.test.", Type: domain.TypeSOA, Content: "ns1. ns2. 100 3600 600"},
		},
		failListRecords: true,
	}
	srv := NewServer(":0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "fallbackerr.test.", QType: packet.IXFR})
	req.Authorities = append(req.Authorities, packet.DNSRecord{
		Name: "fallbackerr.test.", Type: packet.SOA, Serial: 50, // History missing -> fallback
	})

	conn := &mockTCPConn{}
	srv.handleIXFR(conn, req)

	if len(conn.captured) == 0 {
		t.Fatalf("Expected SERVFAIL response for fallback list error, got no response")
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
