package server

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type recursiveResolver struct {
	rootHints []string
	fallbacks []string
}

// recursiveTimeout is the maximum time allowed for recursive resolution.
// Defaults to 30s but can be overridden in tests.
var recursiveTimeout = 30 * time.Second

// newRecursiveResolver creates a recursive resolver with IANA root server hints and fallback resolvers.
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
		fallbacks: []string{
			"8.8.8.8", // Google
			"1.1.1.1", // Cloudflare
		},
	}
}

// getShuffledRoots returns root hints rotated by a random offset for unpredictable ordering.
func (r *recursiveResolver) getShuffledRoots() []string {
	shuffled := make([]string, len(r.rootHints))
	copy(shuffled, r.rootHints)
	// Use crypto/rand to pick a random rotation offset, preventing predictable
	// root server ordering that could be exploited in amplification attacks.
	var offset uint64
	_ = binary.Read(rand.Reader, binary.BigEndian, &offset)
	rotate := int(offset % uint64(len(shuffled)))
	// Rotate left by rotate positions
	result := append(shuffled[rotate:], shuffled[:rotate]...)
	return result
}

// resolveRecursive performs iterative DNS resolution starting from root servers.
func (s *Server) resolveRecursive(name string, qType packet.QueryType) (*packet.DNSPacket, error) {
	// Total timeout to prevent indefinite blocking on failing root servers
	const errRecursiveTimeout = "recursive resolution timeout"
	resolveStart := time.Now()

	// Start with a random root server for load balancing and resilience.
	resolver := newRecursiveResolver()
	roots := resolver.getShuffledRoots()

	var lastErr error

	// Failover logic: Iterate through available root servers (limit to 3 for performance)
	maxRoots := 3
	if len(roots) < maxRoots {
		maxRoots = len(roots)
	}

	for i := 0; i < maxRoots; i++ {
		// Check total resolution timeout
		if time.Since(resolveStart) >= recursiveTimeout {
			s.Logger.Warn("recursive resolution timed out during root iteration", "name", name)
			return nil, errors.New(errRecursiveTimeout)
		}
		rootNS := roots[i]
		ns := rootNS
		currentName := name
		depth := 0

		for depth < 15 { // Increase depth for deep SRV/CNAME chains
			depth++
			s.Logger.Info("recursive lookup", "name", currentName, "type", qType, "ns", ns)

			// Query the current authoritative name server
			serverAddr := net.JoinHostPort(ns, "53")
			resp, err := s.queryFn(serverAddr, currentName, qType)
			if err != nil {
				// Record the error and break the inner loop to try the next root server
				lastErr = err
				s.Logger.Warn("recursive query failed", "ns", ns, "error", err)
				break 
			}

			s.Logger.Debug("recursive response received", 
				"ns", ns, 
				"rcode", resp.Header.ResCode, 
				"answers", len(resp.Answers),
				"auths", len(resp.Authorities),
				"extras", len(resp.Resources),
				"truncated", resp.Header.TruncatedMessage)

			// Handle Truncation (TC bit) - Fallback to TCP
			if resp.Header.TruncatedMessage {
				s.Logger.Info("response truncated, falling back to TCP", "ns", ns)
				tcpResp, errTCP := s.sendTCPQuery(serverAddr, currentName, qType)
				if errTCP == nil {
					resp = tcpResp
				} else {
					s.Logger.Warn("TCP fallback failed", "ns", ns, "error", errTCP)
				}
			}

			// If we got a valid answer with NOERROR, we are done
			if len(resp.Answers) > 0 && resp.Header.ResCode == 0 {
				// Check for CNAME in answers
				var cnameTarget string
				for _, ans := range resp.Answers {
					if ans.Type == packet.CNAME {
						cnameTarget = ans.Host
						break
					}
				}

				if cnameTarget != "" && qType != packet.CNAME {
					s.Logger.Info("following CNAME referral", "from", currentName, "to", cnameTarget)
					currentName = cnameTarget
					// Restart from a root for the new name
					ns = roots[0]
					continue
				}

				return resp, nil
			}

			// NXDOMAIN is a definitive answer, so we stop here
			if resp.Header.ResCode == 3 {
				return resp, nil
			}

			// Follow the referral chain: check Authority section for the next NS
			if nsIP, found := s.findNextNS(resp); found {
				s.Logger.Debug("following referral", "next_ns", nsIP)
				ns = nsIP
				continue
			}

			// Special case for record types that might return 0 answers with NOERROR (CAA, SRV)
			if (qType == packet.CAA || qType == packet.SRV) && resp.Header.ResCode == 0 && len(resp.Answers) == 0 {
				return resp, nil
			}

			s.Logger.Info("recursion reached end of chain without conclusive answer", "name", currentName, "rcode", resp.Header.ResCode)
			break
		}
	}

	// 2. Fallback Strategy: Use reliable upstream resolvers if iterative resolution failed
	// Check total resolution timeout before attempting fallbacks
	if time.Since(resolveStart) >= recursiveTimeout {
		s.Logger.Warn("recursive resolution timed out before fallback", "name", name)
		return nil, errors.New(errRecursiveTimeout)
	}
	s.Logger.Info("iterative resolution failed or inconclusive, trying fallbacks", "name", name)
	for _, fallback := range resolver.fallbacks {
		// Check total resolution timeout before each fallback query
		if time.Since(resolveStart) >= recursiveTimeout {
			s.Logger.Warn("recursive resolution timed out during fallback", "name", name)
			return nil, errors.New(errRecursiveTimeout)
		}
		serverAddr := net.JoinHostPort(fallback, "53")
		// Use sendQueryInternal with RecursionDesired=true for fallbacks
		resp, err := s.sendQueryInternal(serverAddr, name, qType, true)
		if err == nil && (resp.Header.ResCode == 0 || resp.Header.ResCode == 3) {
			s.Logger.Info("fallback resolution successful", "name", name, "fallback", fallback)
			return resp, nil
		}
		if err != nil {
			s.Logger.Warn("fallback query failed", "fallback", fallback, "error", err)
		}
	}

	return nil, fmt.Errorf("recursion failed after trying roots and fallbacks: %w", lastErr)
}

// generateTransactionID returns a cryptographically random 16-bit DNS transaction ID.
func generateTransactionID() uint16 {
	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	return id
}

// sendQuery sends a UDP DNS query to the specified server without recursion desired.
func (s *Server) sendQuery(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
	return s.sendQueryInternal(server, name, qType, false)
}

// sendQueryInternal sends a DNS query and validates the transaction ID in the response.
func (s *Server) sendQueryInternal(server string, name string, qType packet.QueryType, recursive bool) (*packet.DNSPacket, error) {
	conn, err := net.DialTimeout("udp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	req := packet.NewDNSPacket()
	req.Header.ID = generateTransactionID()
	req.Header.Questions = 1
	req.Header.RecursionDesired = recursive
	req.Questions = append(req.Questions, *packet.NewDNSQuestion(name, qType))

	buffer := packet.NewBytePacketBuffer()
	if errWrite := req.Write(buffer); errWrite != nil {
		return nil, errWrite
	}

	_, err = conn.Write(buffer.Buf[:buffer.Position()])
	if err != nil {
		return nil, err
	}

	resBuffer := packet.NewBytePacketBuffer()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	// Read into a temporary buffer first
	tmp := make([]byte, packet.MaxPacketSize)
	n, errRead := conn.Read(tmp)
	if errRead != nil {
		return nil, errRead
	}
	
	// Use Load() to correctly update resBuffer.Len and parsing flag
	resBuffer.Load(tmp[:n])

	resp := packet.NewDNSPacket()
	if errFromBuf := resp.FromBuffer(resBuffer); errFromBuf != nil {
		return nil, errFromBuf
	}

	if resp.Header.ID != req.Header.ID {
		return nil, fmt.Errorf("transaction ID mismatch: expected %d, got %d", req.Header.ID, resp.Header.ID)
	}

	return resp, nil
}

// sendTCPQuery sends a TCP DNS query with a 2-byte length prefix.
func (s *Server) sendTCPQuery(server string, name string, qType packet.QueryType) (*packet.DNSPacket, error) {
	conn, err := net.DialTimeout("tcp", server, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	req := packet.NewDNSPacket()
	req.Header.ID = generateTransactionID()
	req.Header.Questions = 1
	req.Header.RecursionDesired = false
	req.Questions = append(req.Questions, *packet.NewDNSQuestion(name, qType))

	buffer := packet.NewBytePacketBuffer()
	if errWrite := req.Write(buffer); errWrite != nil {
		return nil, errWrite
	}

	data := buffer.Buf[:buffer.Position()]
	fullData := append([]byte{byte((len(data) >> 8) & 0xFF), byte(len(data) & 0xFF)}, data...)
	
	if _, err := conn.Write(fullData); err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	
	resLen := uint16(lenBuf[0])<<8 | uint16(lenBuf[1])
	resData := make([]byte, resLen)
	if _, err := io.ReadFull(conn, resData); err != nil {
		return nil, err
	}

	resBuffer := packet.NewBytePacketBuffer()
	resBuffer.Load(resData)
	resp := packet.NewDNSPacket()
	if errFromBuf := resp.FromBuffer(resBuffer); errFromBuf != nil {
		return nil, errFromBuf
	}

	return resp, nil
}

// findNextNS extracts the next nameserver address from a DNS response's authority and additional sections.
func (s *Server) findNextNS(resp *packet.DNSPacket) (string, bool) {
	// 1. Look for NS records in the Authority section and their corresponding glue in Additional
	for _, auth := range resp.Authorities {
		if auth.Type == packet.NS {
			for _, res := range resp.Resources {
				if strings.EqualFold(res.Name, auth.Host) && res.Type == packet.A {
					return res.IP.String(), true
				}
			}
		}
	}

	// 2. If no glue was found, but we have an NS record, we'd need to resolve THAT NS first.
	// For now, let's see if we can find any other A record in the additional section that might be useful.
	for _, res := range resp.Resources {
		if res.Type == packet.A {
			return res.IP.String(), true
		}
	}

	return "", false
}
