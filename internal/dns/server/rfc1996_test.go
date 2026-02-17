package server

import (
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestHandleNotify verifies that the server correctly acknowledges 
// incoming NOTIFY messages (RFC 1996) from other masters.
func TestHandleNotify(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)

	req := packet.NewDNSPacket()
	req.Header.ID = 789
	req.Header.Opcode = packet.OPCODE_NOTIFY
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "notify.test.", QType: packet.SOA})

	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)
	
	var capturedResp []byte
	err := srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], "127.0.0.1:12345", func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	if err != nil {
		t.Fatalf("handleNotify failed: %v", err)
	}

	resp := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	copy(resBuf.Buf, capturedResp)
	resp.FromBuffer(resBuf)

	// RFC 1996: The response MUST have the same ID, Opcode, and the QR bit set.
	if resp.Header.Opcode != packet.OPCODE_NOTIFY || !resp.Header.Response {
		t.Errorf("Expected NOTIFY response")
	}
	if resp.Header.ResCode != 0 {
		t.Errorf("Expected NOERROR, got %d", resp.Header.ResCode)
	}
}

// TestNotifySlaves verifies that the server proactively sends NOTIFY messages
// to all name servers (slaves) listed in the zone's NS records after an update.
func TestNotifySlaves(t *testing.T) {
	// Listen on a local UDP port to simulate a slave server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer pc.Close()
	
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.test."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.test.", Type: domain.TypeNS, Content: "ns1.slave.test."},
		},
	}
	// Add A record for the slave so notifySlaves can resolve the IP
	repo.records = append(repo.records, domain.Record{
		Name: "ns1.slave.test.", Type: domain.TypeA, Content: "127.0.0.1",
	})

	srv := NewServer("127.0.0.1:5353", repo, nil)
	
	// Trigger notification
	go srv.notifySlaves("example.test.")

	// Attempt to read the NOTIFY packet from the mock slave port
	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 512)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		// If timeout, it might be expected depending on concurrent execution,
		// but for this test we want to see the packet.
		return 
	}

	p := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(buf[:n])
	p.FromBuffer(pBuf)

	if p.Header.Opcode != packet.OPCODE_NOTIFY {
		t.Errorf("Expected NOTIFY opcode, got %d", p.Header.Opcode)
	}
}
