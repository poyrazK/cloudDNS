package repository

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestDNSSECConverters_Extra(t *testing.T) {
	tests := []struct {
		name     string
		domain   domain.Record
		validate func(*testing.T, packet.DNSRecord)
	}{
		{
			name: "DNSKEY",
			domain: domain.Record{
				Type:    domain.RecordType("DNSKEY"),
				Content: "256 3 13 " + base64.StdEncoding.EncodeToString([]byte("pubkey")),
			},
			validate: func(t *testing.T, p packet.DNSRecord) {
				if p.Type != packet.DNSKEY || p.Flags != 256 || string(p.PublicKey) != "pubkey" {
					t.Errorf("DNSKEY conversion failed: %+v", p)
				}
			},
		},
		{
			name: "DS",
			domain: domain.Record{
				Type:    domain.RecordType("DS"),
				Content: "123 13 2 " + hex.EncodeToString([]byte("digest")),
			},
			validate: func(t *testing.T, p packet.DNSRecord) {
				if p.Type != packet.DS || p.KeyTag != 123 || string(p.Digest) != "digest" {
					t.Errorf("DS conversion failed: %+v", p)
				}
			},
		},
		{
			name: "RRSIG",
			domain: domain.Record{
				Type:    domain.RecordType("RRSIG"),
				Content: "1 13 3 300 1000 500 123 signer.com. " + base64.StdEncoding.EncodeToString([]byte("sig")),
			},
			validate: func(t *testing.T, p packet.DNSRecord) {
				if p.Type != packet.RRSIG || p.TypeCovered != 1 || p.SignerName != "signer.com." || string(p.Signature) != "sig" {
					t.Errorf("RRSIG conversion failed: %+v", p)
				}
			},
		},
		{
			name: "NSEC",
			domain: domain.Record{
				Type:    domain.RecordType("NSEC"),
				Content: "next.com. " + hex.EncodeToString([]byte("bitmap")),
			},
			validate: func(t *testing.T, p packet.DNSRecord) {
				if p.Type != packet.NSEC || p.NextName != "next.com." || string(p.TypeBitMap) != "bitmap" {
					t.Errorf("NSEC conversion failed: %+v", p)
				}
			},
		},
		{
			name: "NSEC3",
			domain: domain.Record{
				Type:    domain.RecordType("NSEC3"),
				Content: "1 1 10 " + hex.EncodeToString([]byte("salt")) + " " + hex.EncodeToString([]byte("next")) + " " + hex.EncodeToString([]byte("bm")),
			},
			validate: func(t *testing.T, p packet.DNSRecord) {
				if p.Type != packet.NSEC3 || p.HashAlg != 1 || string(p.Salt) != "salt" {
					t.Errorf("NSEC3 conversion failed: %+v", p)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ConvertDomainToPacketRecord(tt.domain)
			if err != nil {
				t.Fatalf("ConvertDomainToPacketRecord failed: %v", err)
			}
			tt.validate(t, p)

			// Round trip back to domain
			back, err := ConvertPacketRecordToDomain(p, "z1")
			if err != nil {
				t.Fatalf("ConvertPacketRecordToDomain failed: %v", err)
			}
			if back.Type != tt.domain.Type {
				t.Errorf("Round-trip type mismatch: got %v, want %v", back.Type, tt.domain.Type)
			}
		})
	}
}

func TestDNSSECConverters_Errors(t *testing.T) {
	// Test malformed SOA - using empty string or non-numeric for serial should fail
	_, err := ConvertDomainToPacketRecord(domain.Record{Type: domain.TypeSOA, Content: "ns1.com admin.com NaN 3600 600 1209600 300"})
	if err == nil {
		t.Errorf("Expected error for malformed SOA serial")
	}

	// Test malformed DNSSEC types
	_, err = ConvertDomainToPacketRecord(domain.Record{Type: domain.RecordType("DNSKEY"), Content: "abc def ghi jkl"})
	if err == nil {
		t.Errorf("Expected error for non-numeric fields in DNSKEY")
	}
}
