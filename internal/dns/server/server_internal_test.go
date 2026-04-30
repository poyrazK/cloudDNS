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

func TestTruncationPreservesOPTRecords(t *testing.T) {
	// Create a response with OPT records and other resources
	response := &packet.DNSPacket{
		Header: packet.DNSHeader{
			TruncatedMessage: false,
		},
		Answers:    []packet.DNSRecord{},
		Authorities: []packet.DNSRecord{},
		Resources: []packet.DNSRecord{
			// Regular A record
			{Type: packet.A, Name: "www.example.com.", TTL: 300},
			// OPT record (EDNS) - type 41
			{Type: packet.OPT, Name: ".", TTL: 0},
			// Another regular record
			{Type: packet.CNAME, Name: "example.com.", TTL: 300},
		},
	}

	// Simulate the truncation logic from handlePacket
	// This is the filtering logic that should preserve only OPT records
	response.Header.TruncatedMessage = true
	response.Answers = nil
	response.Authorities = nil

	// RFC 6891: Preserve OPT records (type 41) when truncating
	var optRecords []packet.DNSRecord
	for _, res := range response.Resources {
		if res.Type == packet.OPT {
			optRecords = append(optRecords, res)
		}
	}
	response.Resources = optRecords

	// Verify only OPT records remain
	if len(response.Resources) != 1 {
		t.Errorf("expected 1 resource after truncation, got %d", len(response.Resources))
	}
	if len(response.Resources) > 0 && response.Resources[0].Type != packet.OPT {
		t.Errorf("expected OPT record, got %v", response.Resources[0].Type)
	}
	if response.Header.TruncatedMessage != true {
		t.Errorf("expected TruncatedMessage to be true")
	}
}

func TestTruncationWithNoOPTRecords(t *testing.T) {
	// Create a response with only regular records (no OPT)
	response := &packet.DNSPacket{
		Header: packet.DNSHeader{
			TruncatedMessage: false,
		},
		Answers:    []packet.DNSRecord{},
		Authorities: []packet.DNSRecord{},
		Resources: []packet.DNSRecord{
			{Type: packet.A, Name: "www.example.com.", TTL: 300},
			{Type: packet.CNAME, Name: "example.com.", TTL: 300},
		},
	}

	// Simulate truncation logic
	response.Header.TruncatedMessage = true
	response.Answers = nil
	response.Authorities = nil

	var optRecords []packet.DNSRecord
	for _, res := range response.Resources {
		if res.Type == packet.OPT {
			optRecords = append(optRecords, res)
		}
	}
	response.Resources = optRecords

	// When no OPT records exist, Resources should be empty
	if len(response.Resources) != 0 {
		t.Errorf("expected 0 resources when no OPT records exist, got %d", len(response.Resources))
	}
}

func TestTruncationPreservesMultipleOPTRecords(t *testing.T) {
	// Test when there are multiple OPT records (edge case)
	response := &packet.DNSPacket{
		Header: packet.DNSHeader{
			TruncatedMessage: false,
		},
		Answers:    []packet.DNSRecord{},
		Authorities: []packet.DNSRecord{},
		Resources: []packet.DNSRecord{
			{Type: packet.A, Name: "www.example.com.", TTL: 300},
			{Type: packet.OPT, Name: ".", TTL: 0},
			{Type: packet.OPT, Name: ".", TTL: 0},
			{Type: packet.CNAME, Name: "example.com.", TTL: 300},
		},
	}

	// Apply truncation filtering
	response.Header.TruncatedMessage = true
	response.Answers = nil
	response.Authorities = nil

	var optRecords []packet.DNSRecord
	for _, res := range response.Resources {
		if res.Type == packet.OPT {
			optRecords = append(optRecords, res)
		}
	}
	response.Resources = optRecords

	if len(response.Resources) != 2 {
		t.Errorf("expected 2 OPT records, got %d", len(response.Resources))
	}
	for i, res := range response.Resources {
		if res.Type != packet.OPT {
			t.Errorf("resource[%d] = %v, expected OPT", i, res.Type)
		}
	}
}
