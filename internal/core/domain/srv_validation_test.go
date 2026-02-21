package domain

import (
	"testing"
)

func TestValidateSRVContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"Valid SRV", "10 5 5060 sipserver.example.com.", false},
		{"Zero values", "0 0 0 .", false},
		{"Too few parts", "10 5 5060", true},
		{"Too many parts", "10 5 5060 sip.com. extra", true},
		{"Non-numeric priority", "abc 5 5060 sip.com.", true},
		{"Non-numeric weight", "10 abc 5060 sip.com.", true},
		{"Non-numeric port", "10 5 xyz sip.com.", true},
		{"Priority out of range", "70000 5 5060 sip.com.", true},
		{"Weight out of range", "10 70000 5060 sip.com.", true},
		{"Port out of range", "10 5 70000 sip.com.", true},
		{"Negative priority", "-1 5 5060 sip.com.", true},
		{"Negative weight", "10 -1 5060 sip.com.", true},
		{"Negative port", "10 5 -1 sip.com.", true},
		{"Target not FQDN", "10 5 5060 sipserver", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSRVContent(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSRVContent(%s) error = %v, wantErr %v", tt.content, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSRVFields(t *testing.T) {
	p := 10
	w := 5
	port := 5060
	target := "sipserver.example.com."

	err := ValidateSRVFields(&p, &w, &port, target)
	if err != nil {
		t.Errorf("ValidateSRVFields failed: %v", err)
	}

	// Nil fields
	if err := ValidateSRVFields(nil, &w, &port, target); err == nil {
		t.Errorf("Expected error for nil priority")
	}

	// Out of range
	invalidP := 70000
	if err := ValidateSRVFields(&invalidP, &w, &port, target); err == nil {
		t.Errorf("Expected error for out of range priority")
	}

	// Invalid target
	if err := ValidateSRVFields(&p, &w, &port, "invalid"); err == nil {
		t.Errorf("Expected error for invalid target")
	}
}
