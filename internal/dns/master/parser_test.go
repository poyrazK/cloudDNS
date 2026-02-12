package master

import (
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestMasterParser_Parse(t *testing.T) {
	zoneFile := `
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. (
        2023101001 ; serial
        3600       ; refresh
        600        ; retry
        1209600    ; expire
        3600       ; minimum
    )
    IN  NS  ns1.example.com.
www IN  A   1.2.3.4
    IN  A   1.2.3.5 ; Multiple A records for same name
mail 1800 IN MX 10 mail.example.com.
`

	parser := NewMasterParser()
	data, err := parser.Parse(strings.NewReader(zoneFile))
	if err != nil {
		t.Fatalf("Failed to parse zone: %v", err)
	}

	if data.Zone.Name != "example.com." {
		t.Errorf("Expected origin example.com., got %s", data.Zone.Name)
	}

	expectedRecords := []struct {
		name    string
		qType   domain.RecordType
		content string
		ttl     int
	}{
		{"example.com.", domain.TypeSOA, "ns1.example.com. admin.example.com. 2023101001 3600 600 1209600 3600", 3600},
		{"example.com.", domain.TypeNS, "ns1.example.com.", 3600},
		{"www.example.com.", domain.TypeA, "1.2.3.4", 3600},
		{"www.example.com.", domain.TypeA, "1.2.3.5", 3600},
		{"mail.example.com.", domain.TypeMX, "10 mail.example.com.", 1800},
	}

	if len(data.Records) != len(expectedRecords) {
		t.Fatalf("Expected %d records, got %d", len(expectedRecords), len(data.Records))
	}

	for i, exp := range expectedRecords {
		got := data.Records[i]
		if got.Name != exp.name {
			t.Errorf("Record %d: expected name %s, got %s", i, exp.name, got.Name)
		}
		if got.Type != exp.qType {
			t.Errorf("Record %d: expected type %s, got %s", i, exp.qType, got.Type)
		}
		if got.TTL != exp.ttl {
			t.Errorf("Record %d: expected TTL %d, got %d", i, exp.ttl, got.TTL)
		}
		// Content matching might be slightly different due to spacing, 
		// but strings.Fields + strings.Join handles it in parser.
		if got.Content != exp.content {
			t.Errorf("Record %d: expected content '%s', got '%s'", i, exp.content, got.Content)
		}
	}
}
