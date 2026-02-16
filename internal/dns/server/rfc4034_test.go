package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// RFC 4034: Authenticated Denial of Existence (NSEC)
func TestRFC4034_NSEC(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{ID: "r1", ZoneID: "z1", Name: "example.com.", Type: domain.TypeSOA, Content: "ns1.example.com. admin.example.com. 1 2 3 4 5"},
			{ID: "r2", ZoneID: "z1", Name: "a.example.com.", Type: domain.TypeA, Content: "1.1.1.1"},
			{ID: "r3", ZoneID: "z1", Name: "z.example.com.", Type: domain.TypeA, Content: "2.2.2.2"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// 1. Query for non-existent name "b.example.com." with DO bit set
	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "b.example.com.", QType: packet.A})
	req.Resources = append(req.Resources, packet.DNSRecord{
		Name: ".", Type: packet.OPT, UDPPayloadSize: 4096, Z: 0x8000, // DO bit
	})
	
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

	if resPacket.Header.ResCode != 3 {
		t.Errorf("Expected NXDOMAIN (3), got %d", resPacket.Header.ResCode)
	}

	// RFC 4034: Response MUST contain NSEC record in Authority section
	foundNSEC := false
	for _, auth := range resPacket.Authorities {
		if auth.Type == packet.NSEC {
			foundNSEC = true
			// Based on canonical order: a.example.com. -> z.example.com.
			// Query "b" falls between "a" and "z".
			if auth.Name != "a.example.com." {
				t.Errorf("RFC 4034 Violation: NSEC owner name mismatch. Expected a.example.com., got %s", auth.Name)
			}
			if auth.NextName != "z.example.com." {
				t.Errorf("RFC 4034 Violation: NSEC next name mismatch. Expected z.example.com., got %s", auth.NextName)
			}
		}
	}

	if !foundNSEC {
		t.Errorf("RFC 4034 Violation: Missing NSEC record in NXDOMAIN response")
	}
}
