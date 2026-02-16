package server

import (
	"net"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestResolveRecursive(t *testing.T) {
	s := NewServer(":0", nil, nil)

	// Mock queryFn to simulate iterative lookups
	s.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.ID = 1234
		resp.Header.Response = true

		// Handle ANY root server by delegation to .com
		if strings.Contains(server, ":53") && !strings.HasPrefix(server, "1.1.1.1") {
			resp.Authorities = append(resp.Authorities, packet.DNSRecord{
				Name: "com.",
				Type: packet.NS,
				Host: "ns1.com-server.net.",
			})
			resp.Resources = append(resp.Resources, packet.DNSRecord{
				Name: "ns1.com-server.net.",
				Type: packet.A,
				IP:   net.ParseIP("1.1.1.1"),
			})
		} else if strings.HasPrefix(server, "1.1.1.1") {
			// .com server returns final answer
			resp.Answers = append(resp.Answers, packet.DNSRecord{
				Name: name,
				Type: qtype,
				TTL:  300,
				IP:   net.ParseIP("10.20.30.40"),
			})
		}

		return resp, nil
	}

	resp, err := s.resolveRecursive("test.com.")
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

	s.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		resp.Header.ResCode = 3 // NXDOMAIN
		return resp, nil
	}

	resp, err := s.resolveRecursive("nonexistent.io.")
	if err != nil {
		t.Fatalf("Expected no error for NXDOMAIN, got %v", err)
	}

	if resp.Header.ResCode != 3 {
		t.Errorf("Expected RCODE 3, got %d", resp.Header.ResCode)
	}
}

func TestRecursive_NoNextNS(t *testing.T) {
	s := NewServer(":0", nil, nil)

	s.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		// No answers, no authorities, no resources -> findNextNS returns false
		return resp, nil
	}

	resp, err := s.resolveRecursive("deadend.test.")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(resp.Answers) != 0 {
		t.Errorf("Expected no answers")
	}
}

func TestSendQuery(t *testing.T) {
	// 1. Start a mock UDP DNS server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil { t.Fatalf("ResolveUDPAddr failed: %v", err) }
	
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { t.Fatalf("ListenUDP failed: %v", err) }
	
	go func() {
		defer func() { _ = conn.Close() }() 
		buf := make([]byte, 512)
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil { return }
		
		req := packet.NewDNSPacket()
		pb := packet.NewBytePacketBuffer()
		pb.Load(buf[:n])
		_ = req.FromBuffer(pb)
		
		resp := packet.NewDNSPacket()
		resp.Header.ID = req.Header.ID
		resp.Header.Response = true
		if len(req.Questions) > 0 {
			resp.Questions = append(resp.Questions, req.Questions[0])
			resp.Answers = append(resp.Answers, packet.DNSRecord{
				Name: req.Questions[0].Name,
				Type: packet.A,
				IP:   net.ParseIP("9.9.9.9"),
				TTL:  300,
				Class: 1,
			})
		}
		
		resBuf := packet.NewBytePacketBuffer()
		_ = resp.Write(resBuf)
		_, _ = conn.WriteToUDP(resBuf.Buf[:resBuf.Position()], remote)
	}()

	// 2. Call sendQuery
	srv := NewServer(":0", nil, nil)
	serverAddr := conn.LocalAddr().String()
	
	resp, err := srv.sendQuery(serverAddr, "query.test.", packet.A)
	if err != nil {
		t.Fatalf("sendQuery failed: %v", err)
	}
	
	if len(resp.Answers) == 0 || resp.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("sendQuery returned invalid response")
	}
}

func TestNewRecursiveResolver(t *testing.T) {
	r := newRecursiveResolver()
	if len(r.rootHints) == 0 {
		t.Errorf("Expected root hints to be initialized")
	}
}
