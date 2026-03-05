package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

// FuzzServerHandlePacket feeds arbitrary bytes into the high-level server packet handler.
// This tests the protocol state machine (e.g. UPDATE, NOTIFY, AXFR logic) for panics.
func FuzzServerHandlePacket(f *testing.F) {
	// Add some seed packets (e.g. valid update, invalid update)
	
	// Seed 1: A valid, simple A record query
	validQuery := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	f.Add(validQuery)
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x34, 0x28, 0x00, 0x00, 0x01}) // UPDATE Opcode

	f.Fuzz(func(t *testing.T, data []byte) {
		repo := &mockServerRepo{
			zones: []domain.Zone{{ID: "1", Name: "example.com.", TenantID: "t1"}},
			records: []domain.Record{{ZoneID: "1", Name: "example.com.", Type: domain.TypeSOA, Content: "ns. admin. 1 2 3 4 5"}},
		}
		
		srv := NewServer("127.0.0.1:0", repo, nil)
		// Ensure we don't block on network calls during fuzzing
		srv.NotifyPortOverride = 10053 // dummy port

		// handlePacket shouldn't panic, regardless of the input data
		err := srv.handlePacket(data, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, func(resp []byte) error {
			// Dummy sendFn
			return nil
		}, "udp")
		
		_ = err // Error is expected for bad packets, we just want to ensure NO panics
	})
}
