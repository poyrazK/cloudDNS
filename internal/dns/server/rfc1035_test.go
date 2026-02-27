package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// RFC 1035: Message Compression
func TestRFC1035_MessageCompression(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{Name: "www.example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
			{Name: "example.com.", Type: domain.TypeNS, Content: "ns1.example.com.", TTL: 3600},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "www.example.com.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	_ = srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp")

	// Check for compression pointers (0xC0)
	// RFC 1035 Section 4.1.4: "a pointer is an unsigned 16-bit integer with the top two bits set to 1"
	foundCompression := false
	for _, b := range capturedResp {
		if (b & 0xC0) == 0xC0 {
			foundCompression = true
			break
		}
	}
	if !foundCompression {
		t.Errorf("RFC 1035 Violation: Response should use message compression")
	}
}

// RFC 1035: Response Format (Authoritative + Sections)
func TestRFC1035_ResponseFormat(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		records: []domain.Record{
			{Name: "example.com.", Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 1 3600 600 1209600 300", TTL: 3600},
			{Name: "example.com.", Type: domain.TypeNS, Content: "ns1.example.com.", TTL: 3600},
			{Name: "ns1.example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 3600},
			{Name: "www.example.com.", Type: domain.TypeA, Content: "5.6.7.8", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "www.example.com.", QType: packet.A})
	
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	_ = srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	}, "udp")

	resPacket := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(resBuf)

	// RFC 1035: AA bit should be set for authoritative answers
	if !resPacket.Header.AuthoritativeAnswer {
		t.Errorf("RFC 1035 Violation: AA bit not set for authoritative answer")
	}

	// Verify sections
	if len(resPacket.Answers) == 0 {
		t.Errorf("RFC 1035 Violation: Answer section empty")
	}
	if len(resPacket.Authorities) == 0 {
		t.Errorf("RFC 1035 Violation: Authority section (NS) missing")
	}
	if len(resPacket.Resources) == 0 {
		t.Errorf("RFC 1035 Violation: Additional section (Glue) missing")
	}
}

// RFC 1035: Zone Transfers (AXFR)
func TestRFC1035_AXFR(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "axfr.test."},
		},
		records: []domain.Record{
			{ID: "r1", ZoneID: "z1", Name: "axfr.test.", Type: domain.TypeSOA, Content: "ns1.axfr.test. admin.axfr.test. 1 3600 600 1209600 300", TTL: 3600},
			{ID: "r2", ZoneID: "z1", Name: "axfr.test.", Type: domain.TypeNS, Content: "ns1.axfr.test.", TTL: 3600},
			{ID: "r3", ZoneID: "z1", Name: "www.axfr.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Mock TCP pipe
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	req := packet.NewDNSPacket()
	req.Header.ID = 0x1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "axfr.test.", QType: packet.AXFR})
	
	// Handle AXFR in background
	go srv.handleAXFR(serverConn, req)

	// Read stream: RFC 1035 requires SOA first and SOA last
	// We expect: SOA, NS, A, SOA (4 packets)
	receivedCount := 0
	var firstRecordType, lastRecordType packet.QueryType

	for i := 0; i < 4; i++ {
		lenBuf := make([]byte, 2)
		n, _ := clientConn.Read(lenBuf)
		if n != 2 { break }
		
		respLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1]) // #nosec G602
		respData := make([]byte, respLen)
		_, _ = clientConn.Read(respData)

		respPacket := packet.NewDNSPacket()
		pBuf := packet.NewBytePacketBuffer()
		pBuf.Load(respData)
		_ = respPacket.FromBuffer(pBuf)

		if len(respPacket.Answers) > 0 {
			if i == 0 { firstRecordType = respPacket.Answers[0].Type }
			lastRecordType = respPacket.Answers[0].Type
			receivedCount++
		}
	}

	if receivedCount != 4 {
		t.Errorf("RFC 1035 Violation: Expected 4 records in AXFR stream, got %d", receivedCount)
	}
	if firstRecordType != packet.SOA {
		t.Errorf("RFC 1035 Violation: AXFR stream must start with SOA")
	}
	if lastRecordType != packet.SOA {
		t.Errorf("RFC 1035 Violation: AXFR stream must end with SOA")
	}
}

func TestHandleAXFR_ErrorPaths(t *testing.T) {
	// 1. Non-existent zone
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	conn := &mockTCPConn{}
	req := packet.NewDNSPacket()
	req.Header.ID = 1
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "missing.zone.", QType: packet.AXFR})
	
	srv.handleAXFR(conn, req)
	if len(conn.captured) != 1 {
		t.Errorf("Expected NXDOMAIN response")
	}

	// 2. Zone exists but no SOA
	repo.zones = append(repo.zones, domain.Zone{ID: "z1", Name: "nosoa.zone."})
	req.Questions[0].Name = "nosoa.zone."
	conn.captured = nil
	srv.handleAXFR(conn, req)
	if len(conn.captured) != 1 {
		t.Errorf("Expected SERVFAIL response")
	}
}
