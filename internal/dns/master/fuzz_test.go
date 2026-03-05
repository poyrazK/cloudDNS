package master

import (
	"bytes"
	"testing"
)

// FuzzZoneFileParse feeds arbitrary text strings into the zone file parser.
// It ensures that malformed BIND zone files don't cause panics.
func FuzzZoneFileParse(f *testing.F) {
	// Valid seed
	validZone := `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. (
	2021010101 ; Serial
	3600       ; Refresh
	600        ; Retry
	604800     ; Expire
	86400      ; Minimum TTL
)
@ IN NS ns1.example.com.
www IN A 1.2.3.4
`
	f.Add([]byte(validZone))
	f.Add([]byte{})
	f.Add([]byte("example.com. IN A 1.2.3.4\nmissing_ttl IN A 2.3.4.5"))
	f.Add([]byte("example.com. IN TXT \"unclosed string"))

	f.Fuzz(func(t *testing.T, data []byte) {
		reader := bytes.NewReader(data)
		parser := NewMasterParser()
		
		// Parsing should not panic. It will likely return errors, which is fine.
		_, _ = parser.Parse(reader)
	})
}
