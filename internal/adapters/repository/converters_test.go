package repository

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestConvertPacketRecordToDomain(t *testing.T) {
	zoneID := "z1"

	tests := []struct {
		name    string
		pRec    packet.DnsRecord
		want    domain.Record
		wantErr bool
	}{
		{
			name: "A record",
			pRec: packet.DnsRecord{
				Name: "www.test.",
				Type: packet.A,
				TTL:  300,
				IP:   net.ParseIP("1.2.3.4"),
			},
			want: domain.Record{
				ZoneID:  zoneID,
				Name:    "www.test.",
				Type:    domain.TypeA,
				Content: "1.2.3.4",
				TTL:     300,
			},
		},
		{
			name: "MX record",
			pRec: packet.DnsRecord{
				Name:     "test.",
				Type:     packet.MX,
				TTL:      600,
				Priority: 10,
				Host:     "mail.test.",
			},
			want: domain.Record{
				ZoneID:   zoneID,
				Name:     "test.",
				Type:     domain.TypeMX,
				Content:  "mail.test.",
				TTL:      600,
				Priority: intPtr(10),
			},
		},
		{
			name: "TXT record",
			pRec: packet.DnsRecord{
				Name: "test.",
				Type: packet.TXT,
				TTL:  300,
				Txt:  "v=spf1",
			},
			want: domain.Record{
				ZoneID:  zoneID,
				Name:    "test.",
				Type:    domain.TypeTXT,
				Content: "v=spf1",
				TTL:     300,
			},
		},
		{
			name: "SOA record",
			pRec: packet.DnsRecord{
				Name:    "test.",
				Type:    packet.SOA,
				TTL:     300,
				MName:   "ns1.test.",
				RName:   "admin.test.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minimum: 300,
			},
			want: domain.Record{
				ZoneID:  zoneID,
				Name:    "test.",
				Type:    domain.TypeSOA,
				Content: "ns1.test. admin.test. 1 3600 600 604800 300",
				TTL:     300,
			},
		},
		{
			name: "Unsupported type",
			pRec: packet.DnsRecord{
				Type: packet.QueryType(999),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertPacketRecordToDomain(tt.pRec, zoneID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertPacketRecordToDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Name != tt.want.Name || got.Type != tt.want.Type || got.Content != tt.want.Content || got.TTL != tt.want.TTL {
					t.Errorf("ConvertPacketRecordToDomain() got = %v, want %v", got, tt.want)
				}
				if tt.want.Priority != nil {
					if got.Priority == nil || *got.Priority != *tt.want.Priority {
						t.Errorf("Priority mismatch: got %v, want %v", got.Priority, tt.want.Priority)
					}
				}
			}
		})
	}
}

func TestConvertDomainToPacketRecord(t *testing.T) {
	tests := []struct {
		name    string
		rec     domain.Record
		want    packet.DnsRecord
		wantErr bool
	}{
		{
			name: "A record",
			rec: domain.Record{
				Name:    "www.test",
				Type:    domain.TypeA,
				Content: "1.2.3.4",
				TTL:     300,
			},
			want: packet.DnsRecord{
				Name: "www.test.",
				Type: packet.A,
				IP:   net.ParseIP("1.2.3.4"),
				TTL:  300,
			},
		},
		{
			name: "CNAME record",
			rec: domain.Record{
				Name:    "alias",
				Type:    domain.TypeCNAME,
				Content: "target.test",
				TTL:     300,
			},
			want: packet.DnsRecord{
				Name: "alias.",
				Type: packet.CNAME,
				Host: "target.test.",
				TTL:  300,
			},
		},
		{
			name: "SOA record",
			rec: domain.Record{
				Name:    "test.",
				Type:    domain.TypeSOA,
				Content: "ns1.test admin.test 1 3600 600 604800 300",
				TTL:     300,
			},
			want: packet.DnsRecord{
				Name:    "test.",
				Type:    packet.SOA,
				MName:   "ns1.test.",
				RName:   "admin.test.",
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minimum: 300,
			},
		},
		{
			name: "Unsupported type",
			rec: domain.Record{
				Type: "UNKNOWN",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertDomainToPacketRecord(tt.rec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertDomainToPacketRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Name != tt.want.Name || got.Type != tt.want.Type {
					t.Errorf("Field mismatch: got.Name=%s, want.Name=%s, got.Type=%v, want.Type=%v", got.Name, tt.want.Name, got.Type, tt.want.Type)
				}
				if tt.want.IP != nil && got.IP.String() != tt.want.IP.String() {
					t.Errorf("IP mismatch: got %v, want %v", got.IP, tt.want.IP)
				}
				if tt.want.Host != "" && got.Host != tt.want.Host {
					t.Errorf("Host mismatch: got %s, want %s", got.Host, tt.want.Host)
				}
				if got.Type == packet.SOA {
					if got.MName != tt.want.MName || got.RName != tt.want.RName || got.Serial != tt.want.Serial {
						t.Errorf("SOA field mismatch: got %+v, want %+v", got, tt.want)
					}
				}
			}
		})
	}
}

func intPtr(i int) *int { return &i }
