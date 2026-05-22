package domain

import (
	"testing"
)

func TestValidateZoneName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"example.com.", false},
		{"a.b.c.", false},
		{"label-with-hyphen.com.", false},
		{"", true},
		{".", false}, // Root zone IS valid according to code
		{"too-long-label-" + string(make([]byte, 50)) + ".com.", true},
		{"-start-with-hyphen.com.", true},
		{"end-with-hyphen-.com.", true},
		{"invalid_char.com.", true},
		{"missing-trailing-dot.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateZoneName(tt.name); (err != nil) != tt.wantErr {
				t.Errorf("ValidateZoneName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTSIGName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"example.com.", false},
		{"tsig-key", false},
		{"a.b.c", false},
		{"", true},
		{"toolonglabel-" + string(make([]byte, 50)) + ".com.", true},
		{"invalid\x00char.com.", true},
		{"../traversal.com.", true},
		{"/slash.com.", true},
		{"-start.com.", true},
		{"end-.com.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTSIGName(tt.name); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTSIGName(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  Record
		wantErr bool
	}{
		{
			name: "Valid A",
			record: Record{
				Name:    "www.example.com.",
				Type:    TypeA,
				Content: "1.2.3.4",
			},
			wantErr: false,
		},
		{
			name: "Invalid A - IP",
			record: Record{
				Name:    "www.example.com.",
				Type:    TypeA,
				Content: "invalid",
			},
			wantErr: true,
		},
		{
			name: "Valid AAAA",
			record: Record{
				Name:    "www.example.com.",
				Type:    TypeAAAA,
				Content: "2001:db8::1",
			},
			wantErr: false,
		},
		{
			name: "Invalid AAAA - IPv4",
			record: Record{
				Name:    "www.example.com.",
				Type:    TypeAAAA,
				Content: "1.2.3.4",
			},
			wantErr: true,
		},
		{
			name: "Valid CNAME",
			record: Record{
				Name:    "alias.example.com.",
				Type:    TypeCNAME,
				Content: "target.example.com.",
			},
			wantErr: false,
		},
		{
			name: "Invalid CNAME - No Dot",
			record: Record{
				Name:    "alias.example.com.",
				Type:    TypeCNAME,
				Content: "target.example.com",
			},
			wantErr: true,
		},
		{
			name: "Valid SRV",
			record: Record{
				Name:     "_sip._tcp.example.com.",
				Type:     TypeSRV,
				Content:  "target.example.com.",
				Priority: intPtr(10),
				Weight:   intPtr(20),
				Port:     intPtr(5060),
			},
			wantErr: false,
		},
		{
			name: "Invalid SRV - Missing Fields",
			record: Record{
				Name:    "_sip._tcp.example.com.",
				Type:    TypeSRV,
				Content: "target.example.com.",
			},
			wantErr: true,
		},
		{
			name: "Valid CAA",
			record: Record{
				Name:    "example.com.",
				Type:    TypeCAA,
				Content: "0 issue \"letsencrypt.org\"",
			},
			wantErr: false,
		},
		{
			name: "Invalid CAA - Malformed",
			record: Record{
				Name:    "example.com.",
				Type:    TypeCAA,
				Content: "invalid",
			},
			wantErr: true,
		},
		{
			name: "Empty Name",
			record: Record{
				Name:    "",
				Type:    TypeA,
				Content: "1.2.3.4",
			},
			wantErr: true,
		},
		{
			name: "Invalid Type",
			record: Record{
				Name:    "www.example.com.",
				Type:    "INVALID",
				Content: "blah",
			},
			wantErr: true,
		},
		{
			name: "Valid TXT",
			record: Record{
				Name:    "example.com.",
				Type:    TypeTXT,
				Content: "v=spf1 include:_spf.google.com ~all",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateRecord(&tt.record); (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateZoneRole(t *testing.T) {
	tests := []struct {
		name         string
		role         string
		masterServer string
		wantErr      bool
	}{
		{"Valid Master", "master", "", false},
		{"Valid Slave", "slave", "1.2.3.4", false},
		{"Empty Role", "", "", false},
		{"Invalid Role", "proxy", "", true},
		{"Slave Missing Master", "slave", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateZoneRole(tt.role, tt.masterServer); (err != nil) != tt.wantErr {
				t.Errorf("ValidateZoneRole() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func intPtr(i int) *int { return &i }
