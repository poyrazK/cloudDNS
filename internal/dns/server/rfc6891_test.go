package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// RFC 6891: EDNS(0) Support
func TestRFC6891_EDNS0(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{Name: "www.example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// 1. Test query with OPT record
	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "www.example.com.", QType: packet.A})
	
	// Add OPT record with 4096 buffer size and DO bit set
	optReq := packet.DNSRecord{
		Name:           ".",
		Type:           packet.OPT,
		UDPPayloadSize: 4096,
		Z:              0x8000, // DO bit
	}
	req.Resources = append(req.Resources, optReq)
	
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

	// RFC 6891: Response MUST contain an OPT record if the query had one
	foundOPT := false
	for _, res := range resPacket.Resources {
		if res.Type == packet.OPT {
			foundOPT = true
			if res.UDPPayloadSize != 4096 {
				t.Errorf("Expected server to advertise its buffer size (4096), got %d", res.UDPPayloadSize)
			}
			if (res.Z & 0x8000) == 0 {
				t.Errorf("RFC 6891 Violation: DO bit should be mirrored if server supports it")
			}
		}
	}
	if !foundOPT {
		t.Errorf("RFC 6891 Violation: Expected OPT record in response")
	}
}

// RFC 6891: Large payload support without truncation
func TestRFC6891_LargePayload(t *testing.T) {
	// Create a zone with many records to exceed 512 bytes
	var records []domain.Record
	for i := 0; i < 20; i++ {
		records = append(records, domain.Record{
			Name: "big.test.", Type: domain.TypeTXT, Content: "This is a very long text record to increase the packet size significantly.", TTL: 300,
		})
	}
	
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "big.test."}},
		records: records,
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Query WITH EDNS (4096)
	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "big.test.", QType: packet.TXT})
	req.Resources = append(req.Resources, packet.DNSRecord{
		Name: ".", Type: packet.OPT, UDPPayloadSize: 4096,
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

	if resPacket.Header.TruncatedMessage {
		t.Errorf("RFC 6891 Violation: Packet should NOT be truncated when EDNS payload size allows it")
	}
	if len(resPacket.Answers) < 20 {
		t.Errorf("Expected at least 20 TXT records, got %d", len(resPacket.Answers))
	}
}
