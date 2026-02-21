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
		{"Priority out of range", "70000 5 5060 sip.com.", true},
		{"Negative weight", "10 -1 5060 sip.com.", true},
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
