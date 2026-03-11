package domain

import (
	"testing"
)

func TestValidateCAAContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"Valid CAA", "0 issue \"letsencrypt.org\"", false},
		{"Valid CAA with multiple spaces", "0   issue   \"letsencrypt.org\"", false},
		{"Valid CAA with alphanumeric tag", "0 iNsUe1 \"letsencrypt.org\"", false},
		{"Too few parts", "0 issue", true},
		{"Invalid flag (non-numeric)", "abc issue \"letsencrypt.org\"", true},
		{"Invalid flag (out of range)", "256 issue \"letsencrypt.org\"", true},
		{"Invalid flag (negative)", "-1 issue \"letsencrypt.org\"", true},
		{"Invalid tag (non-alphanumeric)", "0 issue! \"letsencrypt.org\"", true},
		{"Unquoted value", "0 issue letsencrypt.org", true},
		{"Value missing starting quote", "0 issue letsencrypt.org\"", true},
		{"Value missing ending quote", "0 issue \"letsencrypt.org", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAAContent(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCAAContent(%s) error = %v, wantErr %v", tt.content, err, tt.wantErr)
			}
		})
	}
}
