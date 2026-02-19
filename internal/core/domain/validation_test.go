package domain

import "testing"

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
