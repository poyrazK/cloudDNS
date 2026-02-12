package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestRFCCompliance_AuthoritativeSections(t *testing.T) {
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

	// 1. Test Positive Answer with NS and Glue
	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "www.example.com.", QType: packet.A})
	
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDnsPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	resPacket.FromBuffer(resBuf)

	if len(resPacket.Answers) != 1 || resPacket.Answers[0].IP.String() != "5.6.7.8" {
		t.Errorf("Expected Answer: 5.6.7.8, got %v", resPacket.Answers)
	}
	if len(resPacket.Authorities) == 0 || resPacket.Authorities[0].Type != packet.NS {
		t.Errorf("Expected NS in Authority section")
	}
	if len(resPacket.Resources) == 0 || resPacket.Resources[0].IP.String() != "1.2.3.4" {
		t.Errorf("Expected Glue record (A) in Additional section")
	}

	// 2. Test NXDOMAIN with SOA in Authority
	req = packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "missing.example.com.", QType: packet.A})
	reqBuf.Reset()
	req.Write(reqBuf)

	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket = packet.NewDnsPacket()
	resBuf.Reset()
	copy(resBuf.Buf, capturedResp)
	resPacket.FromBuffer(resBuf)

	if resPacket.Header.ResCode != 3 {
		t.Errorf("Expected NXDOMAIN (3), got %d", resPacket.Header.ResCode)
	}
	if len(resPacket.Authorities) == 0 || resPacket.Authorities[0].Type != packet.SOA {
		t.Errorf("Expected SOA in Authority section for NXDOMAIN")
	}
}

func TestRFCCompliance_NameCompression(t *testing.T) {
	// This test verifies that Name Compression is enabled and working
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{Name: "www.example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
			{Name: "example.com.", Type: domain.TypeNS, Content: "ns1.example.com.", TTL: 3600},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "www.example.com.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	// Check if "example.com" appears multiple times as a string or if compression is used.
	foundCompression := false
	for _, b := range capturedResp {
		if (b & 0xC0) == 0xC0 {
			foundCompression = true
			break
		}
	}
	if !foundCompression {
		t.Errorf("Expected name compression pointers (0xC0) in the response buffer")
	}
}

func TestRFCCompliance_CaseInsensitivity(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{Name: "www.example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "WwW.ExAmPlE.CoM.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDnsPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	resPacket.FromBuffer(resBuf)

	if len(resPacket.Answers) == 0 {
		t.Fatalf("Expected answer for mixed-case query, got none")
	}
}

func TestRFCCompliance_AXFR(t *testing.T) {
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

	// AXFR requires a TCP connection. We can mock it using net.Pipe.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	req := packet.NewDnsPacket()
	req.Header.ID = 0x1234
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "axfr.test.", QType: packet.AXFR})
	
	// Run AXFR handler in goroutine
	go srv.handleAXFR(serverConn, req)

	// Read responses from client side
	// Expected: SOA, NS, A, SOA (Total 4 packets)
	receivedCount := 0
	for i := 0; i < 4; i++ {
		lenBuf := make([]byte, 2)
		n, _ := clientConn.Read(lenBuf)
		if n != 2 { break }
		
		respLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
		respData := make([]byte, respLen)
		clientConn.Read(respData)

		respPacket := packet.NewDnsPacket()
		pBuf := packet.NewBytePacketBuffer()
		pBuf.Load(respData)
		respPacket.FromBuffer(pBuf)

		if len(respPacket.Answers) == 0 {
			t.Errorf("Expected answer in AXFR packet %d", i)
			continue
		}
		
		receivedCount++
		// Verify start and end are SOA
		if (i == 0 || i == 3) && respPacket.Answers[0].Type != packet.SOA {
			t.Errorf("Packet %d in AXFR should be SOA", i)
		}
	}

	if receivedCount != 4 {
		t.Errorf("Expected 4 packets in AXFR stream, got %d", receivedCount)
	}
}

func TestRFCCompliance_PTR(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "0.0.127.in-addr.arpa."}},
		records: []domain.Record{
			{Name: "1.0.0.127.in-addr.arpa.", Type: domain.TypePTR, Content: "localhost.", TTL: 3600},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "1.0.0.127.in-addr.arpa.", QType: packet.PTR})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDnsPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	resPacket.FromBuffer(resBuf)

	if len(resPacket.Answers) == 0 {
		t.Fatalf("Expected answer for PTR query, got none")
	}
	if resPacket.Answers[0].Host != "localhost." {
		t.Errorf("Expected host localhost., got %s", resPacket.Answers[0].Host)
	}
}
