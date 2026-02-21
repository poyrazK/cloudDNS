package server

import (
	"net"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// RFC 1034: Domain names are case-insensitive
func TestRFC1034_CaseInsensitivity(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{Name: "www.example.com.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Query with mixed case: WwW.ExAmPlE.CoM.
	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "WwW.ExAmPlE.CoM.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	_ = srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(resBuf)

	if len(resPacket.Answers) == 0 {
		t.Fatalf("RFC 1034 Violation: Expected answer for mixed-case query, got none")
	}
	if resPacket.Answers[0].IP.String() != "1.2.3.4" {
		t.Errorf("Expected 1.2.3.4, got %s", resPacket.Answers[0].IP.String())
	}
}

// RFC 1034: Wildcard Matching
func TestRFC1034_WildcardMatching(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{Name: "*.example.com.", Type: domain.TypeA, Content: "9.9.9.9", TTL: 300},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Query for sub.example.com. -> should match *.example.com.
	req := packet.NewDNSPacket()
	req.Questions = append(req.Questions, packet.DNSQuestion{Name: "sub.example.com.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	_ = req.Write(reqBuf)

	var capturedResp []byte
	_ = srv.handlePacket(reqBuf.Buf[:reqBuf.Position()], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, func(resp []byte) error {
		capturedResp = resp
		return nil
	})

	resPacket := packet.NewDNSPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(capturedResp)
	_ = resPacket.FromBuffer(resBuf)

	if len(resPacket.Answers) == 0 {
		t.Fatalf("RFC 1034 Violation: Wildcard record not found")
	}
	// RFC 1034: The name in the answer should match the query name, not the wildcard name
	if resPacket.Answers[0].Name != "sub.example.com." {
		t.Errorf("RFC 1034 Violation: Expected response name 'sub.example.com.', got '%s'", resPacket.Answers[0].Name)
	}
	if resPacket.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("Expected content 9.9.9.9, got %s", resPacket.Answers[0].IP.String())
	}
}

// RFC 1034: Recursion Logic (Simulated)
func TestRFC1034_Recursion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow recursive lookup test in short mode")
	}
	s := NewServer(":0", nil, nil)

	// Mock queryFn to simulate iterative lookups: Root -> TLD -> Authoritative
			// Mock queryFn to simulate iterative lookups: Root -> TLD -> Authoritative
		// The recursiveResolver's `resolveRecursive` method, which uses this mock,
		// does not inspect the transaction ID of the responses it receives.
		// Therefore, a fixed ID is sufficient for this test's purpose.
		s.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
			resp := packet.NewDNSPacket()
			resp.Header.ID = 1234 // Fixed ID for mock response, not validated by resolveRecursive
			resp.Header.Response = true
	
			if strings.Contains(server, ":53") && !strings.HasPrefix(server, "1.1.1.1") {
				// Root server returns delegation to .com
				resp.Authorities = append(resp.Authorities, packet.DNSRecord{
					Name: "com.", Type: packet.NS, Host: "ns1.tld.",
				})
				resp.Resources = append(resp.Resources, packet.DNSRecord{
					Name: "ns1.tld.", Type: packet.A, IP: net.ParseIP("1.1.1.1"),
				})
			} else if strings.HasPrefix(server, "1.1.1.1") {
				// TLD server returns final answer
				resp.Answers = append(resp.Answers, packet.DNSRecord{
					Name: name, Type: qtype, TTL: 300, IP: net.ParseIP("10.20.30.40"),
				})
			}
			return resp, nil
		}
		resp, err := s.resolveRecursive("test.com.")
	if err != nil {
		t.Fatalf("Recursive resolve failed: %v", err)
	}

	if len(resp.Answers) == 0 {
		t.Errorf("RFC 1034 Violation: Recursive resolver failed to follow referrals")
	} else if resp.Answers[0].IP.String() != "10.20.30.40" {
		t.Errorf("Expected final IP 10.20.30.40, got %s", resp.Answers[0].IP.String())
	}
}
