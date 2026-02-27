package server

import (
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestQueryTypeToRecordType(t *testing.T) {
	tests := []struct {
		qType    packet.QueryType
		expected domain.RecordType
	}{
		{packet.A, domain.TypeA},
		{packet.AAAA, domain.TypeAAAA},
		{packet.CNAME, domain.TypeCNAME},
		{packet.NS, domain.TypeNS},
		{packet.MX, domain.TypeMX},
		{packet.SOA, domain.TypeSOA},
		{packet.TXT, domain.TypeTXT},
		{packet.SRV, domain.TypeSRV},
		{packet.PTR, domain.TypePTR},
		{packet.DS, domain.RecordType("DS")},
		{packet.DNSKEY, domain.RecordType("DNSKEY")},
		{packet.RRSIG, domain.RecordType("RRSIG")},
		{packet.NSEC, domain.RecordType("NSEC")},
		{packet.NSEC3, domain.RecordType("NSEC3")},
		{packet.UNKNOWN, domain.RecordType("")},
	}

	for _, tt := range tests {
		actual := queryTypeToRecordType(tt.qType)
		if actual != tt.expected {
			t.Errorf("queryTypeToRecordType(%v) = %v; expected %v", tt.qType, actual, tt.expected)
		}
	}
}
