package server

import (
	"net"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestDNS64Synthesizer_EmbedIPv4(t *testing.T) {
	synth := NewDNS64Synthesizer(nil)

	tests := []struct {
		name     string
		ipv4     string
		expected string
	}{
		{"simple", "192.0.2.1", "64:ff9b::c000:201"},
		{"zero", "0.0.0.0", "64:ff9b::0.0.0.0"},
		{"max", "255.255.255.255", "64:ff9b::ffff:ffff"},
		{"private", "10.0.0.1", "64:ff9b::a00:1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4 := net.ParseIP(tt.ipv4)
			ipv6 := synth.embedIPv4(ipv4)
			expected := net.ParseIP(tt.expected)
			if !ipv6.Equal(expected) {
				t.Errorf("embedIPv4(%s) = %s, want %s", tt.ipv4, ipv6, expected)
			}
		})
	}
}

func TestDNS64Synthesizer_EmbedIPv4_NotIPv4(t *testing.T) {
	synth := NewDNS64Synthesizer(nil)
	// IPv6 address should return nil
	ipv6 := net.ParseIP("2001:db8::1")
	result := synth.embedIPv4(ipv6)
	if result != nil {
		t.Errorf("embedIPv4(IPv6) = %s, want nil", result)
	}
}

func TestDNS64Synthesizer_IsDNS64Applicable(t *testing.T) {
	synth := NewDNS64Synthesizer(nil)

	aRecord := packet.DNSRecord{
		Name:  "example.com.",
		Type:  packet.A,
		Class: 1,
		TTL:   300,
		IP:    net.ParseIP("192.0.2.1"),
	}

	tests := []struct {
		name        string
		qType       packet.QueryType
		aaaaRecords []packet.DNSRecord
		aRecords    []packet.DNSRecord
		want        bool
	}{
		{
			name:        "applicable",
			qType:       packet.AAAA,
			aaaaRecords: nil,
			aRecords:    []packet.DNSRecord{aRecord},
			want:        true,
		},
		{
			name:        "not_aaaa",
			qType:       packet.A,
			aaaaRecords: nil,
			aRecords:    []packet.DNSRecord{aRecord},
			want:        false,
		},
		{
			name:        "has_aaaa",
			qType:       packet.AAAA,
			aaaaRecords: []packet.DNSRecord{{Name: "example.com.", Type: packet.AAAA}},
			aRecords:    []packet.DNSRecord{aRecord},
			want:        false,
		},
		{
			name:        "no_a_records",
			qType:       packet.AAAA,
			aaaaRecords: nil,
			aRecords:    nil,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := synth.IsDNS64Applicable(tt.qType, tt.aaaaRecords, tt.aRecords)
			if got != tt.want {
				t.Errorf("IsDNS64Applicable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNS64Synthesizer_SynthesizeAAAA(t *testing.T) {
	synth := NewDNS64Synthesizer(nil)

	aRecords := []packet.DNSRecord{
		{
			Name:  "example.com.",
			Type:  packet.A,
			Class: 1,
			TTL:   300,
			IP:    net.ParseIP("192.0.2.1"),
		},
		{
			Name:  "example.com.",
			Type:  packet.A,
			Class: 1,
			TTL:   600,
			IP:    net.ParseIP("192.0.2.2"),
		},
	}

	aaaaRecords := synth.SynthesizeAAAA(aRecords, "example.com.", 300)

	if len(aaaaRecords) != 2 {
		t.Fatalf("expected 2 AAAA records, got %d", len(aaaaRecords))
	}

	expectedIPs := []string{"64:ff9b::c000:201", "64:ff9b::c000:202"}
	for i, expected := range expectedIPs {
		if !aaaaRecords[i].IP.Equal(net.ParseIP(expected)) {
			t.Errorf("AAAA record %d = %s, want %s", i, aaaaRecords[i].IP, expected)
		}
		if aaaaRecords[i].Type != packet.AAAA {
			t.Errorf("AAAA record %d type = %v, want AAAA", i, aaaaRecords[i].Type)
		}
		if aaaaRecords[i].TTL != 300 {
			t.Errorf("AAAA record %d TTL = %d, want 300", i, aaaaRecords[i].TTL)
		}
	}
}

func TestDNS64Synthesizer_SynthesizeAAAA_IgnoresNonARecords(t *testing.T) {
	synth := NewDNS64Synthesizer(nil)

	mixedRecords := []packet.DNSRecord{
		{
			Name:  "example.com.",
			Type:  packet.A,
			Class: 1,
			TTL:   300,
			IP:    net.ParseIP("192.0.2.1"),
		},
		{
			Name:  "example.com.",
			Type:  packet.CNAME,
			Class: 1,
			TTL:   300,
		},
		{
			Name:  "example.com.",
			Type:  packet.AAAA,
			Class: 1,
			TTL:   300,
			IP:    net.ParseIP("2001:db8::1"),
		},
	}

	aaaaRecords := synth.SynthesizeAAAA(mixedRecords, "example.com.", 300)

	// Should only synthesize from the single A record
	if len(aaaaRecords) != 1 {
		t.Fatalf("expected 1 AAAA record, got %d", len(aaaaRecords))
	}

	expectedIP := net.ParseIP("64:ff9b::c000:201")
	if !aaaaRecords[0].IP.Equal(expectedIP) {
		t.Errorf("AAAA record = %s, want %s", aaaaRecords[0].IP, expectedIP)
	}
}

func TestDNS64Synthesizer_CustomPrefix(t *testing.T) {
	customPrefix := net.ParseIP("2001:db8:64::")
	synth := NewDNS64Synthesizer(customPrefix)

	ipv4 := net.ParseIP("192.0.2.1")
	ipv6 := synth.embedIPv4(ipv4)

	// Should use custom prefix instead of default
	expected := net.ParseIP("2001:db8:64::c000:201")
	if !ipv6.Equal(expected) {
		t.Errorf("embedIPv4 with custom prefix = %s, want %s", ipv6, expected)
	}
}
