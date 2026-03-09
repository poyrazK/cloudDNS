package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestDNSCookies_RFC7873(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "cookie.test.", TenantID: "t1"},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "www.cookie.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}

	dnsAddr := "127.0.0.1:10059"
	dnsSrv := NewServer(dnsAddr, repo, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = dnsSrv.Run(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// 1. Query with Client Cookie (8 bytes)
	clientCookie := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "www.cookie.test.", QType: packet.A})
	
	opt := packet.DNSRecord{
		Name:           ".",
		Type:           packet.OPT,
		UDPPayloadSize: 4096,
	}
	opt.SetOption(packet.EdnsOptionCookie, clientCookie)
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

	res := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(respBuf[:n])
	_ = res.FromBuffer(resBuf)

	// 2. Verify Cookie in response
	var respCookie []byte
	foundCookie := false
	for _, r := range res.Resources {
		if r.Type == packet.OPT {
			if data, ok := r.GetOption(packet.EdnsOptionCookie); ok {
				respCookie = data
				foundCookie = true
				break
			}
		}
	}

	if !foundCookie {
		t.Errorf("Expected COOKIE option in response")
	}

	// Response cookie should be Client Cookie (8) + Server Cookie (8-32)
	// Our implementation returns 8 + 16 = 24 bytes
	if len(respCookie) < 16 {
		t.Errorf("Response cookie too short: %d bytes", len(respCookie))
	}

	for i := 0; i < 8; i++ {
		if respCookie[i] != clientCookie[i] {
			t.Errorf("Client cookie part mismatch at index %d: expected %02x, got %02x", i, clientCookie[i], respCookie[i])
		}
	}

	// 3. Subsequent query with the same cookie should be accepted (verified manually by coverage or looking at logs)
}
