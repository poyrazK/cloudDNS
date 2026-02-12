package services

import (
	"context"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type mockRepo struct {
	zones   []domain.Zone
	records []domain.Record
}

func (m *mockRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	var res []domain.Record
	for _, r := range m.records {
		if r.Name == name && (qType == "" || r.Type == qType) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	var res []string
	for _, r := range m.records {
		if r.Name == name && r.Type == domain.TypeA {
			res = append(res, r.Content)
		}
	}
	return res, nil
}

func (m *mockRepo) GetZone(ctx context.Context, name string) (*domain.Zone, error) {
	for _, z := range m.zones {
		if z.Name == name {
			return &z, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	var res []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockRepo) CreateZone(ctx context.Context, zone *domain.Zone) error {
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockRepo) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error {
	m.zones = append(m.zones, *zone)
	m.records = append(m.records, records...)
	return nil
}

func (m *mockRepo) CreateRecord(ctx context.Context, record *domain.Record) error {
	m.records = append(m.records, *record)
	return nil
}

func (m *mockRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	return m.zones, nil
}

func (m *mockRepo) DeleteZone(ctx context.Context, id, tenantID string) error   { return nil }
func (m *mockRepo) DeleteRecord(ctx context.Context, id, zoneID string) error { return nil }

func (m *mockRepo) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error { return nil }
func (m *mockRepo) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	return nil, nil
}
func (m *mockRepo) Ping(ctx context.Context) error { return nil }

func TestCreateZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo)

	zone := &domain.Zone{Name: "example.com.", TenantID: "t1"}
	err := svc.CreateZone(context.Background(), zone)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if zone.ID == "" {
		t.Errorf("Expected UUID to be generated")
	}

	if zone.Name != "example.com." {
		t.Errorf("Expected trailing dot, got %s", zone.Name)
	}
}

func TestDeleteZone(t *testing.T) {
	repo := &auditMockRepo{}
	svc := NewDNSService(repo)

	err := svc.DeleteZone(context.Background(), "z1", "t1")
	if err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}

	if len(repo.logs) != 1 {
		t.Fatalf("Expected 1 audit log, got %d", len(repo.logs))
	}
	if repo.logs[0].Action != "DELETE_ZONE" {
		t.Errorf("Expected action DELETE_ZONE, got %s", repo.logs[0].Action)
	}
}

func TestDeleteRecord(t *testing.T) {
	repo := &auditMockRepo{}
	svc := NewDNSService(repo)

	err := svc.DeleteRecord(context.Background(), "r1", "z1")
	if err != nil {
		t.Fatalf("DeleteRecord failed: %v", err)
	}

	if len(repo.logs) != 1 {
		t.Fatalf("Expected 1 audit log, got %d", len(repo.logs))
	}
	if repo.logs[0].Action != "DELETE_RECORD" {
		t.Errorf("Expected action DELETE_RECORD, got %s", repo.logs[0].Action)
	}
}

func TestImportZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo)

	zoneFile := `
$ORIGIN import.test.
$TTL 3600
@   IN  SOA ns1.import.test. admin.import.test. 1 2 3 4 5
www IN  A   1.2.3.4
`
	ctx := context.Background()
	zone, err := svc.ImportZone(ctx, "t1", strings.NewReader(zoneFile))
	if err != nil {
		t.Fatalf("ImportZone failed: %v", err)
	}

	if zone.Name != "import.test." {
		t.Errorf("Expected zone name import.test., got %s", zone.Name)
	}

	// Verify records were created in repo
	if len(repo.records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(repo.records))
	}
}

func TestImportZone_Error(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo)

	// Malformed (missing fields)
	malformed := "$ORIGIN test.com.\nwww A"
	_, err := svc.ImportZone(context.Background(), "t1", strings.NewReader(malformed))
	
	// Master parser currently skips lines it can't parse rather than returning error 
	// unless io.Reader fails. But we can check if it handled correctly.
	if err != nil {
		t.Errorf("Expected skip/partial rather than fatal err, got %v", err)
	}
}
