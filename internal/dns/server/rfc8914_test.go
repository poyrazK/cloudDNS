package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestRFC8914_EDE(t *testing.T) {
	repo := &mockServerRepo{} // Empty repo
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDnsPacket()
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "not-here.test.", QType: packet.A})
	// Include OPT to enable EDE
	req.Resources = append(req.Resources, packet.DnsRecord{
		Type: packet.OPT,
		UDPPayloadSize: 4096,
	})

	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)

	var capturedResp []byte
	srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	res := packet.NewDnsPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	res.FromBuffer(resBuf)

	// Check for EDE in OPT
	foundEDE := false
	for _, r := range res.Resources {
		if r.Type == packet.OPT {
			for _, opt := range r.Options {
				if opt.Code == 15 {
					foundEDE = true
					if len(opt.Data) < 2 {
						t.Errorf("EDE data too short")
					}
					infoCode := uint16(opt.Data[0])<<8 | uint16(opt.Data[1])
					if infoCode != packet.EDE_OTHER {
						t.Errorf("Expected EDE_OTHER (0), got %d", infoCode)
					}
				}
			}
		}
	}
	if !foundEDE {
		t.Errorf("EDE option not found in response")
	}
}
