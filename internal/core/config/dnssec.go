// Package config provides configuration structures for DNSSEC.
package config

import (
	"encoding/base64"
	"fmt"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// DNSSECConfig holds DNSSEC validation settings including trust anchors.
type DNSSECConfig struct {
	// Mode controls validation behavior: "disabled", "ad-bit-only", or "strict"
	Mode string
	// TrustAnchors maps zone name to base64-encoded DNSKEY RDATA.
	// The RDATA format is: flags(2) + protocol(1) + algorithm(1) + publickey
	TrustAnchors map[string]string
}

// ParseTrustAnchor parses a base64-encoded DNSKEY RDATA into a DNSRecord.
func ParseTrustAnchor(base64RDATA string) (packet.DNSRecord, error) {
	data, err := base64.StdEncoding.DecodeString(base64RDATA)
	if err != nil {
		return packet.DNSRecord{}, fmt.Errorf("invalid base64: %w", err)
	}
	if len(data) < 4 {
		return packet.DNSRecord{}, fmt.Errorf("trust anchor too short: need at least 4 bytes, got %d", len(data))
	}
	dnskey := packet.DNSRecord{
		Type: packet.DNSKEY,
		// Name will be set by the caller (zone name)
		Flags:     (uint16(data[0]) << 8) | uint16(data[1]),
		Algorithm: data[2],
	}
	// For ECDSA P-256 (algo 13), the public key is the Q value (32 bytes for P-256)
	// The remaining bytes after flags(2) + protocol(1) + algorithm(1) are the public key
	if len(data) > 4 {
		dnskey.PublicKey = data[4:]
	}
	return dnskey, nil
}

// ToMap converts DNSSECConfig.TrustAnchors to a map of zone -> parsed DNSRecord.
func (c *DNSSECConfig) ToMap() (map[string]packet.DNSRecord, error) {
	result := make(map[string]packet.DNSRecord)
	for zone, anchor := range c.TrustAnchors {
		dnskey, err := ParseTrustAnchor(anchor)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trust anchor for zone %s: %w", zone, err)
		}
		result[zone] = dnskey
	}
	return result, nil
}