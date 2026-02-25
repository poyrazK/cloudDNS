// Package master provides functionality for parsing DNS master zone files (RFC 1035).
package master

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

// MasterParser implements a parser for DNS master zone files.
type MasterParser struct {
	Origin  string
	DefaultTTL int
}

// NewMasterParser creates and returns a new MasterParser instance.
func NewMasterParser() *MasterParser {
	return &MasterParser{
		DefaultTTL: 3600,
	}
}

// ZoneData holds the parsed records and metadata from a zone file.
type ZoneData struct {
	Zone    domain.Zone
	Records []domain.Record
}

// Parse reads a master zone file from the provided reader and returns the parsed data.
func (p *MasterParser) Parse(r io.Reader) (*ZoneData, error) {
	scanner := bufio.NewScanner(r)
	// Use 1MB buffer for long records like DNSKEY/RRSIG
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)
	data := &ZoneData{}
	
	var lastName string
	var inParen bool
	var parenLines []string
	var firstLineLeadingWS bool

	for scanner.Scan() {
		line := scanner.Text()
		
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = line[:idx]
		}

		if !inParen {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" { continue }
			
			firstLineLeadingWS = len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
			
			if strings.Contains(line, "(") {
				inParen = true
				parenLines = append(parenLines, strings.Replace(line, "(", " ", 1))
				if !strings.Contains(line, ")") {
					continue
				}
			}
		} else {
			parenLines = append(parenLines, line)
			if !strings.Contains(line, ")") {
				continue
			}
			inParen = false
		}

		var fullLine string
		if len(parenLines) > 0 {
			fullLine = strings.Join(parenLines, " ")
			fullLine = strings.ReplaceAll(fullLine, ")", " ")
			parenLines = nil
		} else {
			fullLine = line
		}

		trimmedFull := strings.TrimSpace(fullLine)
		if trimmedFull == "" { continue }

		if strings.HasPrefix(trimmedFull, "$") {
			parts := strings.Fields(trimmedFull)
			if len(parts) < 2 { continue }
			switch strings.ToUpper(parts[0]) {
			case "$ORIGIN":
				p.Origin = parts[1]
				if !strings.HasSuffix(p.Origin, ".") { p.Origin += "." }
				data.Zone.Name = p.Origin
			case "$TTL":
				ttl, _ := strconv.Atoi(parts[1])
				p.DefaultTTL = ttl
			}
			continue
		}

		fields := strings.Fields(trimmedFull)
		if len(fields) == 0 { continue }

		var name string
		if firstLineLeadingWS {
			name = lastName
		} else {
			name = fields[0]
			fields = fields[1:]
			if name == "@" {
				name = p.Origin
			} else if !strings.HasSuffix(name, ".") && p.Origin != "" {
				name = name + "." + p.Origin
			}
			lastName = name
		}

		var ttl = p.DefaultTTL
		var qType domain.RecordType
		var dataParts []string

		for i := 0; i < len(fields); i++ {
			f := fields[i]
			upper := strings.ToUpper(f)
			if val, err := strconv.Atoi(f); err == nil {
				ttl = val
				continue
			}
			if upper == "IN" || upper == "CS" || upper == "CH" || upper == "HS" {
				continue
			}
			qType = domain.RecordType(upper)
			dataParts = fields[i+1:]
			break
		}

		if qType == "" || name == "" { continue }

		data.Records = append(data.Records, domain.Record{
			Name:    name,
			Type:    qType,
			Content: strings.Join(dataParts, " "),
			TTL:     ttl,
		})
	}

	return data, scanner.Err()
}

// RFC 4034 Section 6.1: Canonical DNS Name Order
func CompareNamesCanonically(a, b string) int {
	a = strings.TrimSuffix(strings.ToLower(a), ".")
	b = strings.TrimSuffix(strings.ToLower(b), ".")

	if a == b { return 0 }
	if a == "" { return -1 }
	if b == "" { return 1 }

	aLabels := strings.Split(a, ".")
	bLabels := strings.Split(b, ".")

	i := len(aLabels) - 1
	j := len(bLabels) - 1

	for i >= 0 && j >= 0 {
		if aLabels[i] < bLabels[j] { return -1 }
		if aLabels[i] > bLabels[j] { return 1 }
		i--
		j--
	}

	if len(aLabels) < len(bLabels) { return -1 }
	if len(aLabels) > len(bLabels) { return 1 }
	return 0
}

func SortRecordsCanonically(records []domain.Record) {
	sort.Slice(records, func(i, j int) bool {
		cmp := CompareNamesCanonically(records[i].Name, records[j].Name)
		if cmp == 0 {
			return records[i].Type < records[j].Type
		}
		return cmp < 0
	})
}

func RecordTypeToQueryType(t domain.RecordType) uint16 {
	switch t {
	case domain.TypeA: return 1
	case domain.TypeNS: return 2
	case domain.TypeCNAME: return 5
	case domain.TypeSOA: return 6
	case domain.TypeMX: return 15
	case domain.TypeTXT: return 16
	case domain.TypeAAAA: return 28
	case domain.TypePTR: return 12
	default: return 0
	}
}
