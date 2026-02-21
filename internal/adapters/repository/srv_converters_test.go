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
	if pRec.Priority != 10 || pRec.Weight != 20 || pRec.Port != 5060 || pRec.Host != "sipserver.example.com." {
		t.Errorf("Packet fields mismatch: %+v", pRec)
	}

	// 2. Packet to Domain
	decodedDomain, err := ConvertPacketRecordToDomain(pRec, "zone-123")
	if err != nil {
		t.Fatalf("ConvertPacketRecordToDomain failed: %v", err)
	}

	if decodedDomain.Type != domain.TypeSRV {
		t.Errorf("Domain type mismatch: got %v, want %v", decodedDomain.Type, domain.TypeSRV)
	}
	if *decodedDomain.Priority != 10 || *decodedDomain.Weight != 20 || *decodedDomain.Port != 5060 || decodedDomain.Content != "sipserver.example.com." {
		t.Errorf("Domain fields mismatch: %+v", decodedDomain)
	}
}
