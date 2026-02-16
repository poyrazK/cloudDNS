package server

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type recursiveResolver struct {
	rootHints []string
}

func newRecursiveResolver() *recursiveResolver {
	return &recursiveResolver{
		rootHints: []string{
			"198.41.0.4",     // a.root-servers.net
			"170.247.170.2",  // b.root-servers.net
			"192.33.4.12",    // c.root-servers.net
			"199.7.91.13",    // d.root-servers.net
			"192.203.230.10", // e.root-servers.net
			"192.5.5.241",    // f.root-servers.net
			"192.112.36.4",   // g.root-servers.net
			"198.97.190.53",  // h.root-servers.net
			"192.36.148.17",  // i.root-servers.net
			"192.58.128.30",  // j.root-servers.net
			"193.0.14.129",   // k.root-servers.net
			"199.7.83.42",    // l.root-servers.net
			"202.12.27.33",   // m.root-servers.net
		},
	}
}

func (r *recursiveResolver) getShuffledRoots() []string {
	shuffled := make([]string, len(r.rootHints))
	copy(shuffled, r.rootHints)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled
}

func (s *Server) resolveRecursive(name string) (*packet.DNSPacket, error) {
	// Start with a random root server for load balancing and resilience.
	resolver := newRecursiveResolver()
	roots := resolver.getShuffledRoots()

	var lastErr error

	// Failover logic: Iterate through all available root servers.
	// If one fails (timeout, unreachable), proceed to the next.
	for _, rootNS := range roots {
		ns := rootNS
		
		for {
			s.Logger.Info("recursive lookup", "name", name, "ns", ns)

			// Query the current authoritative name server
			serverAddr := net.JoinHostPort(ns, "53")
			resp, err := s.queryFn(serverAddr, name, packet.A)
			if err != nil {
				// Record the error and break the inner loop to try the next root server
				lastErr = err
				s.Logger.Warn("recursive query failed", "ns", ns, "error", err)
				break 
			}

			// If we got a valid answer with NOERROR, we are done
			if len(resp.Answers) > 0 && resp.Header.ResCode == 0 {
				return resp, nil
			}

			// NXDOMAIN is a definitive answer, so we stop here
			if resp.Header.ResCode == 3 {
				return resp, nil
			}

			// Follow the referral chain: check Authority section for the next NS
			if nsIP, found := s.findNextNS(resp); found {
				ns = nsIP
				continue
			}

			// No more referrals or answers, return what we have
			return resp, nil
		}
	}

	return nil, fmt.Errorf("recursion failed after trying all roots: %w", lastErr)
}

func (s *Server) sendQuery(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	req := packet.NewDNSPacket()
	req.Header.ID = 1234
	req.Header.Questions = 1
	req.Header.RecursionDesired = false // Iterative
	req.Questions = append(req.Questions, *packet.NewDNSQuestion(name, packet.A))

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return nil, err
	}

	_, err = conn.Write(buffer.Buf[:buffer.Position()])
	if err != nil {
		return nil, err
	}

	resBuffer := packet.NewBytePacketBuffer()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resBuffer.Buf)
	if err != nil {
		return nil, err
	}
	resBuffer.Buf = resBuffer.Buf[:n]

	resp := packet.NewDNSPacket()
	if err := resp.FromBuffer(resBuffer); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *Server) findNextNS(resp *packet.DNSPacket) (string, bool) {
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