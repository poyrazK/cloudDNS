package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestRFC8914_EDE(t *testing.T) {
	repo := &mockServerRepo{} // Empty repo
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "not-here.test.", QType: packet.A})
	// Include OPT to enable EDE
	req.Resources = append(req.Resources, packet.DNSRecord{
		Type: packet.OPT,
		UDPPayloadSize: 4096,
	})

	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	_ = srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	res := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	_ = res.FromBuffer(resBuf)

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
					if infoCode != packet.EdeOther {
						t.Errorf("Expected EdeOther (0), got %d", infoCode)
					}
				}
			}
		}
	}
	if !foundEDE {
		t.Errorf("EDE option not found in response")
	}
}
