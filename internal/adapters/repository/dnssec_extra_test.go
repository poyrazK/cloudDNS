package repository

import (
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestConvertPacketRecordToDomain_DNSSEC(t *testing.T) {
	zoneID := "test-zone"

	tests := []struct {
		name    string
		pRec    packet.DNSRecord
		wantType string
		contains string
	}{
		{
			name: "DNSKEY",
			pRec: packet.DNSRecord{
				Type:      packet.DNSKEY,
				Flags:     256,
				Algorithm: 13,
				PublicKey: []byte{0x01, 0x02},
			},
			wantType: "DNSKEY",
			contains: "256 3 13 AQI=",
		},
		{
			name: "RRSIG",
			pRec: packet.DNSRecord{
				Type:        packet.RRSIG,
				TypeCovered: 1, // A
				Algorithm:   13,
				Labels:      3,
				OrigTTL:     300,
				Expiration:  1000,
				Inception:   500,
				KeyTag:      123,
				SignerName:  "test.",
				Signature:   []byte{0x03, 0x04},
			},
			wantType: "RRSIG",
			contains: "1 13 3 300 1000 500 123 test. AwQ=",
		},
		{
			name: "NSEC",
			pRec: packet.DNSRecord{
				Type:       packet.NSEC,
				NextName:   "next.",
				TypeBitMap: []byte{0x00, 0x01},
			},
			wantType: "NSEC",
			contains: "next. 0001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dRec, err := ConvertPacketRecordToDomain(tt.pRec, zoneID)
			if err != nil {
				t.Fatalf("ConvertPacketRecordToDomain failed: %v", err)
			}
			if string(dRec.Type) != tt.wantType {
				t.Errorf("got type %s, want %s", dRec.Type, tt.wantType)
			}
			// Use simple logic to check content
			found := false
			if tt.contains == "" {
				found = true
			} else if len(dRec.Content) >= len(tt.contains) {
				// Search for substring
				for i := 0; i <= len(dRec.Content)-len(tt.contains); i++ {
					if dRec.Content[i:i+len(tt.contains)] == tt.contains {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("content %s does not contain %s", dRec.Content, tt.contains)
			}
		})
	}
}
