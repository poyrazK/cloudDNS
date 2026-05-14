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
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	// Verify response: should just be the SOA
	if len(conn.captured) != 1 {
		t.Fatalf("Expected exactly 1 response packet for up-to-date IXFR, got %d", len(conn.captured))
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
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	// Sequence: [Current SOA] -> [Old SOA, Deletions] -> [New SOA, Additions] -> [Current SOA]
	// Our stub implementation sends multiple responses
	if len(conn.captured) < 3 {
		t.Fatalf("Expected multiple response packets for IXFR with changes, got %d", len(conn.captured))
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
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("expected exactly 1 TCP response for missing SOA IXFR, got %d", len(conn.captured))
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
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("expected exactly 1 TCP response for malformed IXFR (no authority SOA), got %d", len(conn.captured))
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
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	if len(conn.captured) != 1 {
		t.Fatalf("expected exactly 1 TCP response for unknown zone IXFR, got %d", len(conn.captured))
	}

	resp := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	pb.Load(conn.captured[0])
	_ = resp.FromBuffer(pb)
	if resp.Header.ResCode != packet.RcodeNxDomain {
		t.Errorf("Expected NXDOMAIN (3), got %d", resp.Header.ResCode)
	}
}

func TestHandleIXFR_InvalidSOA(t *testing.T) {
	tests := []struct {
		name       string
		soaContent string
	}{
		{"too_few_fields", "ns1. ns2."},
		{"non_numeric_serial", "ns1. ns2. not-a-number 3600 600 604800 300"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockServerRepo{
				zones: []domain.Zone{{ID: "z1", Name: "invalid.test."}},
				records: []domain.Record{
					{ZoneID: "z1", Name: "invalid.test.", Type: domain.TypeSOA, Content: tt.soaContent},
				},
			}
			srv := NewServer(":0", repo, nil)

			req := packet.NewDNSPacket()
			req.Questions = append(req.Questions, packet.DNSQuestion{Name: "invalid.test.", QType: packet.IXFR})
			req.Authorities = append(req.Authorities, packet.DNSRecord{
				Name: "invalid.test.", Type: packet.SOA, Class: 1, Serial: 1,
			})

			conn := &mockTCPConn{}
			srv.handleIXFR(context.Background(), conn, req, nil, nil)

			if len(conn.captured) != 1 {
				t.Fatalf("Expected exactly 1 SERVFAIL response for invalid SOA, got %d", len(conn.captured))
			}

			resp := packet.NewDNSPacket()
			pb := packet.NewBytePacketBuffer()
			pb.Load(conn.captured[0])
			_ = resp.FromBuffer(pb)
			if resp.Header.ResCode != packet.RcodeServFail {
				t.Errorf("Expected SERVFAIL, got %d", resp.Header.ResCode)
			}
		})
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
	srv.handleIXFR(context.Background(), conn, req, nil, nil)

	// Should fallback to AXFR. AXFR sequence: SOA, then all records, then SOA.
	// records: SOA, www.gap.test., new.gap.test.
	// Expected responses:
	// 1. Current SOA (Start)
	// 2. www.gap.test. (A)
	// 3. new.gap.test. (A)
	// 4. Current SOA (End)
	if len(conn.captured) != 4 {
		t.Fatalf("Expected exactly 4 responses for AXFR fallback (SOA, A, A, SOA), got %d", len(conn.captured))
	}

	// 1. Verify first record is SOA with serial 10
	resp1 := packet.NewDNSPacket()
	pBuf1 := packet.NewBytePacketBuffer()
	pBuf1.Load(conn.captured[0])
	_ = resp1.FromBuffer(pBuf1)
	if len(resp1.Answers) != 1 || resp1.Answers[0].Type != packet.SOA || resp1.Answers[0].Serial != 10 {
		t.Errorf("Expected first response to be SOA with serial 10, got type %v serial %d", resp1.Answers[0].Type, resp1.Answers[0].Serial)
	}

	// 2. Verify second record is www.gap.test. (A)
	resp2 := packet.NewDNSPacket()
	pBuf2 := packet.NewBytePacketBuffer()
	pBuf2.Load(conn.captured[1])
	_ = resp2.FromBuffer(pBuf2)
	if len(resp2.Answers) != 1 || resp2.Answers[0].Name != "www.gap.test." || resp2.Answers[0].Type != packet.A {
		t.Errorf("Expected second response to be www.gap.test. (A), got name %s type %v", resp2.Answers[0].Name, resp2.Answers[0].Type)
	}

	// 3. Verify third record is new.gap.test. (A)
	resp3 := packet.NewDNSPacket()
	pBuf3 := packet.NewBytePacketBuffer()
	pBuf3.Load(conn.captured[2])
	_ = resp3.FromBuffer(pBuf3)
	if len(resp3.Answers) != 1 || resp3.Answers[0].Name != "new.gap.test." || resp3.Answers[0].Type != packet.A {
		t.Errorf("Expected third response to be new.gap.test. (A), got name %s type %v", resp3.Answers[0].Name, resp3.Answers[0].Type)
	}

	// 4. Verify last record is SOA with serial 10 (End marker)
	resp4 := packet.NewDNSPacket()
	pBuf4 := packet.NewBytePacketBuffer()
	pBuf4.Load(conn.captured[3])
	_ = resp4.FromBuffer(pBuf4)
	if len(resp4.Answers) != 1 || resp4.Answers[0].Type != packet.SOA || resp4.Answers[0].Serial != 10 {
		t.Errorf("Expected last response to be SOA with serial 10, got type %v serial %d", resp4.Answers[0].Type, resp4.Answers[0].Serial)
	}
}

func TestHandleIXFR_ListRecordsErrors(t *testing.T) {
	tests := []struct {
		name   string
		zone   string
		serial uint32
	}{
		{"fallback_gap", "fallbackerr.test.", 50},
		{"fallback_initial", "listerror.test.", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockServerRepo{
				zones: []domain.Zone{{ID: "z1", Name: tt.zone}},
				records: []domain.Record{
					{ZoneID: "z1", Name: tt.zone, Type: domain.TypeSOA, Content: "ns1. ns2. 100 3600 600 604800 300"},
				},
				failListRecords: true,
			}
			srv := NewServer(":0", repo, nil)

			req := packet.NewDNSPacket()
			req.Questions = append(req.Questions, packet.DNSQuestion{Name: tt.zone, QType: packet.IXFR})
			req.Authorities = append(req.Authorities, packet.DNSRecord{
				Name: tt.zone, Type: packet.SOA, Class: 1, Serial: tt.serial,
			})

			conn := &mockTCPConn{}
			srv.handleIXFR(context.Background(), conn, req, nil, nil)

			if len(conn.captured) != 1 {
				t.Fatalf("Expected exactly 1 SERVFAIL response for list records failure, got %d", len(conn.captured))
			}

			resp := packet.NewDNSPacket()
			pb := packet.NewBytePacketBuffer()
			pb.Load(conn.captured[0])
			_ = resp.FromBuffer(pb)
			if resp.Header.ResCode != packet.RcodeServFail {
				t.Errorf("Expected SERVFAIL, got %d", resp.Header.ResCode)
			}
		})
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
