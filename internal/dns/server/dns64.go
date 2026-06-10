package server

import (
	"net"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// DefaultDNS64Prefix is the Well-Known Prefix (WKP) per RFC 6147.
var DefaultDNS64Prefix = net.ParseIP("64:ff9b::")

// DNS64Synthesizer handles DNS64 AAAA record synthesis (RFC 6147).
type DNS64Synthesizer struct {
	prefix net.IP
}

// NewDNS64Synthesizer creates a new DNS64 synthesizer with the given prefix.
// If prefix is nil, DefaultDNS64Prefix (64:ff9b::/96) is used.
func NewDNS64Synthesizer(prefix net.IP) *DNS64Synthesizer {
	if prefix == nil {
		prefix = DefaultDNS64Prefix
	}
	return &DNS64Synthesizer{prefix: prefix}
}

// embedIPv4 embeds an IPv4 address into the DNS64 prefix.
// w.x.y.z becomes 64:ff9b::w.x.y.z
func (s *DNS64Synthesizer) embedIPv4(ipv4 net.IP) net.IP {
	ipv4 = ipv4.To4()
	if ipv4 == nil {
		return nil
	}
	// Validate prefix is a proper IPv6 address (not IPv4) with sufficient bits (/96 or shorter)
	prefix := s.prefix
	if prefix.To4() != nil || prefix.To16() == nil {
		// Invalid prefix, use default
		prefix = DefaultDNS64Prefix
	}
	ipv6 := make(net.IP, 16)
	copy(ipv6, prefix)
	ipv6[12] = ipv4[0]
	ipv6[13] = ipv4[1]
	ipv6[14] = ipv4[2]
	ipv6[15] = ipv4[3]
	return ipv6
}

// SynthesizeAAAA synthesizes AAAA records from A records.
// Each IPv4 address w.x.y.z becomes 64:ff9b::w.x.y.z
// Returns the synthesized AAAA records with appropriate TTL.
func (s *DNS64Synthesizer) SynthesizeAAAA(aRecords []packet.DNSRecord, queryName string, minTTL uint32) []packet.DNSRecord {
	var aaaaRecords []packet.DNSRecord
	for _, aRec := range aRecords {
		if aRec.Type != packet.A {
			continue
		}
		ipv6 := s.embedIPv4(aRec.IP)
		if ipv6 == nil {
			continue
		}
		aaaaRecords = append(aaaaRecords, packet.DNSRecord{
			Name:  queryName,
			Type:  packet.AAAA,
			Class: aRec.Class,
			TTL:   minTTL,
			IP:    ipv6,
		})
	}
	return aaaaRecords
}

// IsDNS64Applicable checks if DNS64 synthesis should be attempted.
// Returns true only when:
// - Query is for AAAA record type
// - No AAAA records exist (NODATA)
// - A records DO exist for the same name
func (s *DNS64Synthesizer) IsDNS64Applicable(qType packet.QueryType, aaaaRecords, aRecords []packet.DNSRecord) bool {
	if qType != packet.AAAA {
		return false
	}
	if len(aaaaRecords) > 0 {
		return false
	}
	if len(aRecords) == 0 {
		return false
	}
	return true
}
