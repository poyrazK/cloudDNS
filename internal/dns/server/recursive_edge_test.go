package server

import (
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestFindNextNS_Logic verifies the internal findNextNS helper logic
// used by the recursive resolver to discover authoritative servers.
func TestFindNextNS_Logic(t *testing.T) {
	srv := &Server{}
	resp := packet.NewDnsPacket()
	
	// 1. Case: No authorities
	if _, found := srv.findNextNS(resp); found {
		t.Errorf("Expected not found for empty packet")
	}

	// 2. Case: Authority present with glue
	resp.Authorities = append(resp.Authorities, packet.DnsRecord{
		Name: "test.", Type: packet.NS, Host: "ns1.test.",
	})
	resp.Resources = append(resp.Resources, packet.DnsRecord{
		Name: "ns1.test.", Type: packet.A, IP: []byte{1, 2, 3, 4},
	})
	
	if ns, found := srv.findNextNS(resp); !found || ns != "1.2.3.4" {
		t.Errorf("Expected 1.2.3.4, got %s (found=%v)", ns, found)
	}
}
