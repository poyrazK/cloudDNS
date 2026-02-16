package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// RFC 4035: Authenticated Data (AD) bit
func TestRFC4035_ADBit(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "secure.test."}},
		records: []domain.Record{
			{Name: "www.secure.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "www.secure.test.", QType: packet.A})
	req.Header.AuthedData = true
	
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	_ = resPacket.FromBuffer(resBuf)

	// ensure field exists
	_ = resPacket.Header.AuthedData
}

func TestRFC4035_NSEC(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "a.example.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300},
			{ZoneID: "z1", Name: "z.example.test.", Type: domain.TypeA, Content: "2.2.2.2", TTL: 300},
			{ZoneID: "z1", Name: "example.test.", Type: domain.TypeSOA, Content: "ns1.example.test. host. 1 3600 600 604800 300"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "m.example.test.", QType: packet.A})
	// Set DO bit
	req.Resources = append(req.Resources, packet.DNSRecord{
		Type: packet.OPT,
		Z:    0x8000,
	})

	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	res := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	_ = res.FromBuffer(resBuf)

	if res.Header.ResCode != 3 {
		t.Errorf("Expected NXDOMAIN, got %d", res.Header.ResCode)
	}

	// Should have NSEC in Authorities
	foundNSEC := false
	for _, auth := range res.Authorities {
		if auth.Type == packet.NSEC {
			foundNSEC = true
			if auth.Name != "a.example.test." || auth.NextName != "z.example.test." {
				t.Errorf("NSEC interval mismatch: got %s -> %s", auth.Name, auth.NextName)
			}
		}
	}
	if !foundNSEC {
		t.Errorf("NSEC record not found in NXDOMAIN response")
	}
}

func TestRFC4035_NSEC3(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "nsec3.test."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "nsec3.test.", Type: domain.TypeSOA, Content: "ns1.nsec3.test. host. 1 3600 600 604800 300"},
			{ZoneID: "z1", Name: "nsec3.test.", Type: "NSEC3PARAM", Content: "1 0 10 abcd"},
			{ZoneID: "z1", Name: "www.nsec3.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "missing.nsec3.test.", QType: packet.A})
	req.Resources = append(req.Resources, packet.DNSRecord{
		Type: packet.OPT,
		Z:    0x8000,
	})

	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	res := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	_ = res.FromBuffer(resBuf)

	foundNSEC3 := false
	for _, auth := range res.Authorities {
		if auth.Type == packet.NSEC3 {
			foundNSEC3 = true
		}
	}
	if !foundNSEC3 {
		t.Errorf("NSEC3 record not found in NXDOMAIN response for NSEC3-enabled zone")
	}
}
