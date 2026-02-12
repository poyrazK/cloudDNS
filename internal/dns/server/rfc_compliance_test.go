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
	// A simple heuristic: if the total packet size is significantly smaller than the sum of string lengths.
	// "www.example.com" (15) + "example.com" (11) + "ns1.example.com" (15) = 41 chars
	// With compression, "example.com" should only be written fully once.
	
	// We can inspect the raw buffer for 0xC0 (compression pointer prefix)
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
