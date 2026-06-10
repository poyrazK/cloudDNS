package server

import (
	"fmt"
	"net"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"hash/fnv"
)

// fnv32 returns a 32-bit FNV-1a hash of the key for cache lock sharding.
func fnv32(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key)) // #nosec G104
	return h.Sum32()
}

// lockKey returns the cache lock shard for the given key using FNV hashing.
func (t *cacheLockTable) lockKey(key string) *cacheLockShard {
	return &t[fnv32(key)%cacheLockShardCount]
}

func rcodeLabel(err error, req *packet.DNSPacket) string {
	if err == nil {
		return fmt.Sprintf("%d", req.Header.ResCode)
	}
	return "0"
}

// extractClientIP extracts the client IP address from the source address.
func extractClientIP(srcAddr interface{}) string {
	switch addr := srcAddr.(type) {
	case string:
		ip, _, _ := net.SplitHostPort(addr)
		return ip
	case net.Addr:
		ip, _, _ := net.SplitHostPort(addr.String())
		return ip
	}
	return ""
}

// parentZoneName returns the parent zone name for a given zone.
// e.g., "www.example.com." -> "example.com." -> "com." -> "." -> ""
// For root zone ("."), returns "" as root has no parent.
func parentZoneName(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return "" // Root zone has no parent
	}
	labels := strings.Split(zone, ".")
	if len(labels) < 2 {
		return "."
	}
	if len(labels) == 2 {
		return labels[len(labels)-1] + "."
	}
	return strings.Join(labels[1:], ".") + "."
}

// queryTypeToRecordType converts a packet query type to a domain record type.
func queryTypeToRecordType(qType packet.QueryType) domain.RecordType {
	switch qType {
	case packet.A:
		return domain.TypeA
	case packet.AAAA:
		return domain.TypeAAAA
	case packet.CNAME:
		return domain.TypeCNAME
	case packet.NS:
		return domain.TypeNS
	case packet.MX:
		return domain.TypeMX
	case packet.SOA:
		return domain.TypeSOA
	case packet.TXT:
		return domain.TypeTXT
	case packet.SRV:
		return domain.TypeSRV
	case packet.PTR:
		return domain.TypePTR
	case packet.CAA:
		return domain.TypeCAA
	case packet.HTTPS:
		return domain.TypeHTTPS
	case packet.DS:
		return domain.RecordType("DS")
	case packet.DNSKEY:
		return domain.RecordType("DNSKEY")
	case packet.RRSIG:
		return domain.RecordType("RRSIG")
	case packet.NSEC:
		return domain.RecordType("NSEC")
	case packet.NSEC3:
		return domain.RecordType("NSEC3")
	case packet.ANY:
		return ""
	default:
		return ""
	}
}