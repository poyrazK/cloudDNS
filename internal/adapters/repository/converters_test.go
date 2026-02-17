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
		pRec    packet.DNSRecord
		want    domain.Record
		wantErr bool
	}{
		{
			name: "A record",
			pRec: packet.DNSRecord{
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
			pRec: packet.DNSRecord{
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
			name: "SRV record",
			pRec: packet.DNSRecord{
				Name:      "_sip._tcp.test.",
				Type:      packet.SRV,
				TTL:       300,
				Priority:  10,
				Weight: 60,
				Port:   5060,
				Host:      "sip.test.",
			},
			want: domain.Record{
				ZoneID:   zoneID,
				Name:     "_sip._tcp.test.",
				Type:     domain.TypeSRV,
				Content:  "sip.test.",
				TTL:      300,
				Priority: intPtr(10),
				Weight:   intPtr(60),
				Port:     intPtr(5060),
			},
		},
		{
			name: "TXT record",
			pRec: packet.DNSRecord{
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
			pRec: packet.DNSRecord{
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
			pRec: packet.DNSRecord{
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
				if tt.want.Weight != nil {
					if got.Weight == nil || *got.Weight != *tt.want.Weight {
						t.Errorf("Weight mismatch: got %v, want %v", got.Weight, tt.want.Weight)
					}
				}
				if tt.want.Port != nil {
					if got.Port == nil || *got.Port != *tt.want.Port {
						t.Errorf("Port mismatch: got %v, want %v", got.Port, tt.want.Port)
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
		want    packet.DNSRecord
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
			want: packet.DNSRecord{
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
			want: packet.DNSRecord{
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
			want: packet.DNSRecord{
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

func TestConvertDomainToPacketRecord_AllTypes(t *testing.T) {
	tests := []struct {
		name string
		rec  domain.Record
		want packet.DNSRecord
	}{
		{
			name: "AAAA record",
			rec: domain.Record{
				Name:    "v6.test.",
				Type:    domain.TypeAAAA,
				Content: "2001:db8::1",
				TTL:     300,
			},
			want: packet.DNSRecord{
				Name: "v6.test.",
				Type: packet.AAAA,
				IP:   net.ParseIP("2001:db8::1"),
			},
		},
		{
			name: "NS record",
			rec: domain.Record{
				Name:    "test.",
				Type:    domain.TypeNS,
				Content: "ns1.provider.com",
				TTL:     3600,
			},
			want: packet.DNSRecord{
				Name: "test.",
				Type: packet.NS,
				Host: "ns1.provider.com.",
			},
		},
		{
			name: "PTR record",
			rec: domain.Record{
				Name:    "1.0.0.127.in-addr.arpa.",
				Type:    domain.TypePTR,
				Content: "localhost.",
				TTL:     3600,
			},
			want: packet.DNSRecord{
				Name: "1.0.0.127.in-addr.arpa.",
				Type: packet.PTR,
				Host: "localhost.",
			},
		},
		{
			name: "TXT record",
			rec: domain.Record{
				Name:    "test.",
				Type:    domain.TypeTXT,
				Content: "simple text",
				TTL:     300,
			},
			want: packet.DNSRecord{
				Name: "test.",
				Type: packet.TXT,
				Txt:  "simple text",
			},
		},
		{
			name: "SRV record",
			rec: domain.Record{
				Name:     "_sip._tcp.test.",
				Type:     domain.TypeSRV,
				Content:  "sip.test",
				TTL:      300,
				Priority: intPtr(10),
				Weight:   intPtr(60),
				Port:     intPtr(5060),
			},
			want: packet.DNSRecord{
				Name:      "_sip._tcp.test.",
				Type:      packet.SRV,
				Priority:  10,
				Weight: 60,
				Port:   5060,
				Host:      "sip.test.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertDomainToPacketRecord(tt.rec)
			if err != nil {
				t.Fatalf("ConvertDomainToPacketRecord failed: %v", err)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type mismatch: got %v, want %v", got.Type, tt.want.Type)
			}
			if tt.want.IP != nil && got.IP.String() != tt.want.IP.String() {
				t.Errorf("IP mismatch")
			}
			if tt.want.Host != "" && got.Host != tt.want.Host {
				t.Errorf("Host mismatch: got %s, want %s", got.Host, tt.want.Host)
			}
			if tt.want.Txt != "" && got.Txt != tt.want.Txt {
				t.Errorf("TXT mismatch")
			}
			if got.Type == packet.SRV {
				if got.Priority != tt.want.Priority {
					t.Errorf("SRV Priority mismatch: got %d, want %d", got.Priority, tt.want.Priority)
				}
				if got.Weight != tt.want.Weight {
					t.Errorf("SRV Weight mismatch: got %d, want %d", got.Weight, tt.want.Weight)
				}
				if got.Port != tt.want.Port {
					t.Errorf("SRV Port mismatch: got %d, want %d", got.Port, tt.want.Port)
				}
			}
		})
	}
}

func intPtr(i int) *int { return &i }
