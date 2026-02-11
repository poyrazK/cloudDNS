package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestResolveRecursive(t *testing.T) {
	s := NewServer(":0", nil, nil)

	// Mock queryFn to simulate iterative lookups
	s.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DnsPacket, error) {
		resp := packet.NewDnsPacket()
		resp.Header.ID = 1234
		resp.Header.Response = true

		if server == "198.41.0.4:53" {
			// Root server returns delegation to .com
			resp.Authorities = append(resp.Authorities, packet.DnsRecord{
				Name: "com.",
				Type: packet.NS,
				Host: "ns1.com-server.net.",
			})
			resp.Resources = append(resp.Resources, packet.DnsRecord{
				Name: "ns1.com-server.net.",
				Type: packet.A,
				IP:   net.ParseIP("1.1.1.1"),
			})
		} else if server == "1.1.1.1:53" {
			// .com server returns final answer
			resp.Answers = append(resp.Answers, packet.DnsRecord{
				Name: name,
				Type: qtype,
				TTL:  300,
				IP:   net.ParseIP("10.20.30.40"),
			})
		}

		return resp, nil
	}

	resp, err := s.resolveRecursive("test.com.", packet.A)
	if err != nil {
		t.Fatalf("Recursive resolve failed: %v", err)
	}

	if len(resp.Answers) == 0 {
		t.Errorf("Expected answer, got none")
	} else if resp.Answers[0].IP.String() != "10.20.30.40" {
		t.Errorf("Expected IP 10.20.30.40, got %s", resp.Answers[0].IP.String())
	}
}

func TestResolveRecursive_NXDOMAIN(t *testing.T) {
	s := NewServer(":0", nil, nil)

	s.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DnsPacket, error) {
		resp := packet.NewDnsPacket()
		resp.Header.Response = true
		resp.Header.ResCode = 3 // NXDOMAIN
		return resp, nil
	}

	resp, err := s.resolveRecursive("nonexistent.io.", packet.A)
	if err != nil {
		t.Fatalf("Expected no error for NXDOMAIN, got %v", err)
	}

	if resp.Header.ResCode != 3 {
		t.Errorf("Expected RCODE 3, got %d", resp.Header.ResCode)
	}
}
