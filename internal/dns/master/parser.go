package master

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type MasterParser struct {
	Origin  string
	DefaultTTL int
}

func NewMasterParser() *MasterParser {
	return &MasterParser{
		DefaultTTL: 3600,
	}
}

type ZoneData struct {
	Zone    domain.Zone
	Records []domain.Record
}

func (p *MasterParser) Parse(r io.Reader) (*ZoneData, error) {
	scanner := bufio.NewScanner(r)
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

		var ttl int = p.DefaultTTL
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
	aLabels := strings.Split(strings.TrimSuffix(strings.ToLower(a), "."), ".")
	bLabels := strings.Split(strings.TrimSuffix(strings.ToLower(b), "."), ".")

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
