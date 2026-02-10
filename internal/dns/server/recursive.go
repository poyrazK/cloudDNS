package server

import (
	"fmt"
	"net"
	"time"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func (s *Server) resolveRecursive(name string, qtype packet.QueryType) (*packet.DnsPacket, error) {
	// 1. Start with a root server (a.root-servers.net)
	ns := "198.41.0.4"

	for {
		fmt.Printf("Attempting recursive lookup of %s %d with ns %s\n", name, qtype, ns)

		// 2. Query the current name server
		serverAddr := net.JoinHostPort(ns, "53")
		resp, err := s.sendQuery(serverAddr, name, qtype)
		if err != nil {
			return nil, err
		}

		// 3. If we have answers and NOERROR, we are done
		if len(resp.Answers) > 0 && resp.Header.ResCode == 0 {
			return resp, nil
		}

		// 4. If we get NXDOMAIN, it's final
		if resp.Header.ResCode == 3 {
			return resp, nil
		}

		// 5. Otherwise, look for the next name server in the Authority section
		if nsIP, found := s.findNextNS(resp); found {
			ns = nsIP
			continue
		}

		// 6. If not found in Additional, we might need to resolve the NS name itself
		return resp, nil
	}
}

func (s *Server) sendQuery(server string, name string, qtype packet.QueryType) (*packet.DnsPacket, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := packet.NewDnsPacket()
	req.Header.ID = 1234
	req.Header.Questions = 1
	req.Header.RecursionDesired = false // Iterative
	req.Questions = append(req.Questions, *packet.NewDnsQuestion(name, qtype))

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return nil, err
	}

	_, err = conn.Write(buffer.Buf[:buffer.Position()])
	if err != nil {
		return nil, err
	}

	resBuffer := packet.NewBytePacketBuffer()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resBuffer.Buf)
	if err != nil {
		return nil, err
	}
	resBuffer.Buf = resBuffer.Buf[:n]

	resp := packet.NewDnsPacket()
	if err := resp.FromBuffer(resBuffer); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Server) findNextNS(resp *packet.DnsPacket) (string, bool) {
	for _, auth := range resp.Authorities {
		if auth.Type == packet.NS {
			for _, res := range resp.Resources {
				if res.Name == auth.Host && res.Type == packet.A {
					return res.IP.String(), true
				}
			}
		}
	}
	for _, res := range resp.Resources {
		if res.Type == packet.A {
			return res.IP.String(), true
		}
	}
	return "", false
}