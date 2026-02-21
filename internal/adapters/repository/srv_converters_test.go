package repository

import (
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestSRVConverters(t *testing.T) {
	priority := 10
	weight := 20
	port := 5060
	
	originalDomain := domain.Record{
		Name:     "service.example.com.",
		Type:     domain.TypeSRV,
		Content:  "sipserver.example.com.",
		TTL:      3600,
		Priority: &priority,
		Weight:   &weight,
		Port:     &port,
	}

	// 1. Domain to Packet
	pRec, err := ConvertDomainToPacketRecord(originalDomain)
	if err != nil {
		t.Fatalf("ConvertDomainToPacketRecord failed: %v", err)
	}

	if pRec.Type != packet.SRV {
		t.Errorf("Packet type mismatch: got %v, want %v", pRec.Type, packet.SRV)
	}
	if pRec.Priority != 10 {
		t.Errorf("Packet priority mismatch: got %d, want %d", pRec.Priority, 10)
	}
	if pRec.Weight != 20 {
		t.Errorf("Packet weight mismatch: got %d, want %d", pRec.Weight, 20)
	}
	if pRec.Port != 5060 {
		t.Errorf("Packet port mismatch: got %d, want %d", pRec.Port, 5060)
	}
	if pRec.Host != "sipserver.example.com." {
		t.Errorf("Packet host mismatch: got %s, want %s", pRec.Host, "sipserver.example.com.")
	}

	// 2. Packet to Domain
	decodedDomain, err := ConvertPacketRecordToDomain(pRec, "zone-123")
	if err != nil {
		t.Fatalf("ConvertPacketRecordToDomain failed: %v", err)
	}

	if decodedDomain.Type != domain.TypeSRV {
		t.Errorf("Domain type mismatch: got %v, want %v", decodedDomain.Type, domain.TypeSRV)
	}
	if decodedDomain.Priority == nil || *decodedDomain.Priority != 10 {
		t.Errorf("Domain priority mismatch: got %v, want %d", decodedDomain.Priority, 10)
	}
	if decodedDomain.Weight == nil || *decodedDomain.Weight != 20 {
		t.Errorf("Domain weight mismatch: got %v, want %d", decodedDomain.Weight, 20)
	}
	if decodedDomain.Port == nil || *decodedDomain.Port != 5060 {
		t.Errorf("Domain port mismatch: got %v, want %d", decodedDomain.Port, 5060)
	}
	if decodedDomain.Content != "sipserver.example.com." {
		t.Errorf("Domain content mismatch: got %s, want %s", decodedDomain.Content, "sipserver.example.com.")
	}
}
