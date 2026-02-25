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
		if got.Content != exp.content {
			t.Errorf("Record %d: expected content '%s', got '%s'", i, exp.content, got.Content)
		}
	}
}

func TestMasterParser_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		zoneFile string
		want     []domain.Record
	}{
		{
			name: "Multiple Origin Changes",
			zoneFile: `
$ORIGIN a.com.
sub  A 1.1.1.1
$ORIGIN b.com.
sub  A 2.2.2.2
`,
			want: []domain.Record{
				{Name: "sub.a.com.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 3600},
				{Name: "sub.b.com.", Type: domain.TypeA, Content: "2.2.2.2", TTL: 3600},
			},
		},
		{
			name: "Comments everywhere",
			zoneFile: `
$ORIGIN root.
; start comment
$TTL 60 ; ttl comment
@ A 1.2.3.4 ; end comment
  ; empty line with comment
  TXT "hello" ; tx comment
`,
			want: []domain.Record{
				{Name: "root.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 60},
				{Name: "root.", Type: domain.TypeTXT, Content: "\"hello\"", TTL: 60},
			},
		},
		{
			name: "Mixed positions",
			zoneFile: `
$ORIGIN test.
a 300 IN A 1.1.1.1
b IN 600 A 2.2.2.2
c A 3.3.3.3
`,
			want: []domain.Record{
				{Name: "a.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300},
				{Name: "b.test.", Type: domain.TypeA, Content: "2.2.2.2", TTL: 600},
				{Name: "c.test.", Type: domain.TypeA, Content: "3.3.3.3", TTL: 3600},
			},
		},
		{
			name: "Tricky multi-line",
			zoneFile: `
$ORIGIN multi.
@ SOA ( ns.
        admin.
        1 ; ser
        2
        3
        4
        5 )
`,
			want: []domain.Record{
				{Name: "multi.", Type: domain.TypeSOA, Content: "ns. admin. 1 2 3 4 5", TTL: 3600},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewMasterParser()
			got, err := p.Parse(strings.NewReader(tt.zoneFile))
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if len(got.Records) != len(tt.want) {
				t.Fatalf("Expected %d records, got %d", len(tt.want), len(got.Records))
			}
			for i, exp := range tt.want {
				g := got.Records[i]
				if g.Name != exp.Name || g.Type != exp.Type || g.TTL != exp.TTL || g.Content != exp.Content {
					t.Errorf("Record %d mismatch: got %+v, want %+v", i, g, exp)
				}
			}
		})
	}
}

func TestCanonicalSorting(t *testing.T) {
	records := []domain.Record{
		{Name: "z.example.com.", Type: domain.TypeA},
		{Name: "a.example.com.", Type: domain.TypeA},
		{Name: "example.com.", Type: domain.TypeSOA},
		{Name: "example.com.", Type: domain.TypeNS},
		{Name: "b.a.example.com.", Type: domain.TypeA},
	}

	SortRecordsCanonically(records)

	// RFC 4034 Expected Order:
	// 1. example.com. (shorter)
	// 2. a.example.com.
	// 3. b.a.example.com.
	// 4. z.example.com.
	
	expectedOrder := []string{
		"example.com.", // NS or SOA (Type check needed for same name)
		"example.com.",
		"a.example.com.",
		"b.a.example.com.",
		"z.example.com.",
	}

	for i, name := range expectedOrder {
		if records[i].Name != name {
			t.Errorf("Pos %d: expected %s, got %s", i, name, records[i].Name)
		}
	}
	
	// Check type sorting for same name (example.com.)
	// NS (2) should come before SOA (6)
	if records[0].Type != domain.TypeNS || records[1].Type != domain.TypeSOA {
		t.Errorf("Type sorting failed for same name: got %v, %v", records[0].Type, records[1].Type)
	}
}

func TestRecordTypeToQueryType(t *testing.T) {
	tests := []struct {
		rt   domain.RecordType
		want uint16
	}{
		{domain.TypeA, 1},
		{domain.TypeNS, 2},
		{domain.TypeCNAME, 5},
		{domain.TypeSOA, 6},
		{domain.TypeMX, 15},
		{domain.TypeTXT, 16},
		{domain.TypeAAAA, 28},
		{domain.TypePTR, 12},
		{"UNKNOWN", 0},
	}
	for _, tt := range tests {
		if got := RecordTypeToQueryType(tt.rt); got != tt.want {
			t.Errorf("RecordTypeToQueryType(%v) = %v, want %v", tt.rt, got, tt.want)
		}
	}
}

func TestMasterParser_LargeRecord(t *testing.T) {
	largeContent := strings.Repeat("a", 100000)
	zoneFile := "root. 3600 IN TXT " + largeContent
	parser := NewMasterParser()
	data, err := parser.Parse(strings.NewReader(zoneFile))
	if err != nil {
		t.Fatalf("Failed to parse large record: %v", err)
	}
	if len(data.Records) != 1 || len(data.Records[0].Content) != 100000 {
		t.Errorf("Large record parsing failed")
	}
}
