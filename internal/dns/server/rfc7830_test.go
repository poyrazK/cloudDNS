package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestEDNSPadding_RFC7830(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "padding.test.", TenantID: "t1"},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "www.padding.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}

	dnsAddr := "127.0.0.1:10060"
	dnsSrv := NewServer(dnsAddr, repo, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = dnsSrv.Run(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// 1. Query with Padding requested (option code 12)
	req := packet.NewDNSPacket()
	req.Header.ID = 5678
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "www.padding.test.", QType: packet.A})
	
	opt := packet.DNSRecord{
		Name:           ".",
		Type:           packet.OPT,
		UDPPayloadSize: 4096,
	}
	// Add an empty padding option to signal request
	opt.SetOption(packet.EdnsOptionPadding, []byte{})
	req.Resources = append(req.Resources, opt)

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := packet.NewBytePacketBuffer()
	_ = req.Write(buf)
	_, _ = conn.Write(buf.Buf[:buf.Position()])

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	// 2. Verify response size is a multiple of block size (468 for responses)
	// Actually, our padResponse implementation uses 468 if response.Header.Response is true.
	if n % 468 != 0 {
		// Wait, the packet length prefix for TCP/DoT is NOT included in n if we are using UDP.
		// For UDP, the whole packet is n.
		// However, some implementations might pad to something smaller or differently.
		// RFC 8467 recommends 468 for responses.
		t.Errorf("Response size %d is not a multiple of 468", n)
	}

	res := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(respBuf[:n])
	_ = res.FromBuffer(resBuf)

	// 3. Verify PADDING option is present
	foundPadding := false
	for _, r := range res.Resources {
		if r.Type == packet.OPT {
			if _, ok := r.GetOption(packet.EdnsOptionPadding); ok {
				foundPadding = true
				break
			}
		}
	}

	if !foundPadding {
		t.Errorf("Expected PADDING option in response")
	}
}
