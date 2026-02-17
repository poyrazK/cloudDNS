package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type mockRepo struct {
	zones   []domain.Zone
	records []domain.Record
	err     error
}

func (m *mockRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	if m.err != nil { return nil, m.err }
	var res []domain.Record
	for _, r := range m.records {
		if r.Name == name && (qType == "" || r.Type == qType) {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	if m.err != nil { return nil, m.err }
	var res []string
	for _, r := range m.records {
		if r.Name == name && r.Type == domain.TypeA {
			res = append(res, r.Content)
		}
	}
	return res, nil
}

func (m *mockRepo) GetZone(ctx context.Context, name string) (*domain.Zone, error) {
	if m.err != nil { return nil, m.err }
	for _, z := range m.zones {
		if z.Name == name {
			return &z, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) ListRecordsForZone(_ context.Context, zoneID string) ([]domain.Record, error) {
	if m.err != nil { return nil, m.err }
	var res []domain.Record
	for _, r := range m.records {
		if r.ZoneID == zoneID {
			res = append(res, r)
		}
	}
	return res, nil
}

func (m *mockRepo) CreateZone(_ context.Context, zone *domain.Zone) error {
	if m.err != nil { return m.err }
	m.zones = append(m.zones, *zone)
	return nil
}

func (m *mockRepo) CreateZoneWithRecords(_ context.Context, zone *domain.Zone, records []domain.Record) error {
	if m.err != nil { return m.err }
	m.zones = append(m.zones, *zone)
	m.records = append(m.records, records...)
	return nil
}

func (m *mockRepo) CreateRecord(_ context.Context, record *domain.Record) error {
	if m.err != nil { return m.err }
	m.records = append(m.records, *record)
	return nil
}

func (m *mockRepo) ListZones(_ context.Context, _ string) ([]domain.Zone, error) {
	if m.err != nil { return nil, m.err }
	return m.zones, nil
}

func (m *mockRepo) DeleteZone(_ context.Context, _, _ string) error   { return m.err }
func (m *mockRepo) DeleteRecord(_ context.Context, _, _ string) error { return m.err }

func (m *mockRepo) DeleteRecordsByNameAndType(_ context.Context, _, _ string, _ domain.RecordType) error {
	return m.err
}

func (m *mockRepo) DeleteRecordsByName(_ context.Context, _, _ string) error {
	return m.err
}

func (m *mockRepo) DeleteRecordSpecific(_ context.Context, _, _ string, _ domain.RecordType, _ string) error {
	return m.err
}

func (m *mockRepo) RecordZoneChange(_ context.Context, _ *domain.ZoneChange) error {
	return m.err
}

func (m *mockRepo) ListZoneChanges(_ context.Context, _ string, _ uint32) ([]domain.ZoneChange, error) {
	return nil, m.err
}

func (m *mockRepo) SaveAuditLog(_ context.Context, _ *domain.AuditLog) error { return m.err }
func (m *mockRepo) GetAuditLogs(_ context.Context, _ string) ([]domain.AuditLog, error) {
	return nil, m.err
}
func (m *mockRepo) Ping(_ context.Context) error { return m.err }

func (m *mockRepo) CreateKey(_ context.Context, _ *domain.DNSSECKey) error { return m.err }
func (m *mockRepo) ListKeysForZone(_ context.Context, _ string) ([]domain.DNSSECKey, error) {
	return nil, m.err
}
func (m *mockRepo) UpdateKey(_ context.Context, _ *domain.DNSSECKey) error { return m.err }

func TestCreateZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo)

	// Case 1: Name with dot
	zone := &domain.Zone{Name: "example.com.", TenantID: "t1"}
	err := svc.CreateZone(context.Background(), zone)
	if err != nil { t.Fatalf("Expected no error, got %v", err) }
	if zone.Name != "example.com." { t.Errorf("Expected example.com., got %s", zone.Name) }

	// Case 2: Name without dot
	zone2 := &domain.Zone{Name: "nodot.com", TenantID: "t1"}
	err = svc.CreateZone(context.Background(), zone2)
	if err != nil { t.Fatalf("Expected no error, got %v", err) }
	if zone2.Name != "nodot.com." { t.Errorf("Expected nodot.com., got %s", zone2.Name) }

	if zone.ID == "" {
		t.Errorf("Expected UUID to be generated")
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
	
	if err != nil {
		t.Errorf("Expected skip/partial rather than fatal err, got %v", err)
	}
}

func TestResolve_Wildcard(t *testing.T) {
	repo := &mockRepo{
		records: []domain.Record{
			{Name: "*.example.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300},
		},
	}
	svc := NewDNSService(repo)

	// Test direct hit on wildcard
	recs, err := svc.Resolve(context.Background(), "www.example.test.", domain.TypeA, "8.8.8.8")
	if err != nil || len(recs) != 1 {
		t.Fatalf("Wildcard resolution failed: %v", err)
	}
	if recs[0].Name != "www.example.test." {
		t.Errorf("Expected name to be rewritten to www.example.test., got %s", recs[0].Name)
	}

	// Test deeper level hit
	recs, _ = svc.Resolve(context.Background(), "a.b.c.example.test.", domain.TypeA, "8.8.8.8")
	if len(recs) != 1 {
		t.Errorf("Deep wildcard resolution failed")
	}
}

func TestListZones(t *testing.T) {
	repo := &mockRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "z1.test."},
			{ID: "z2", Name: "z2.test."},
		},
	}
	svc := NewDNSService(repo)

	zones, err := svc.ListZones(context.Background(), "t1")
	if err != nil || len(zones) != 2 {
		t.Errorf("ListZones failed")
	}
}

func TestHealthCheck(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo)

	if err := svc.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}
}

func TestServiceErrorPaths(t *testing.T) {
	repo := &mockRepo{err: errors.New("db error")}
	svc := NewDNSService(repo)
	ctx := context.Background()

	if err := svc.CreateZone(ctx, &domain.Zone{Name: "test."}); err == nil {
		t.Errorf("Expected error in CreateZone")
	}
	if err := svc.CreateRecord(ctx, &domain.Record{}); err == nil {
		t.Errorf("Expected error in CreateRecord")
	}
	if _, err := svc.Resolve(ctx, "test.", domain.TypeA, ""); err == nil {
		t.Errorf("Expected error in Resolve")
	}
	if _, err := svc.ListZones(ctx, ""); err == nil {
		t.Errorf("Expected error in ListZones")
	}
	if err := svc.DeleteZone(ctx, "z1", ""); err == nil {
		t.Errorf("Expected error in DeleteZone")
	}
	if err := svc.DeleteRecord(ctx, "r1", ""); err == nil {
		t.Errorf("Expected error in DeleteRecord")
	}
	if _, err := svc.ImportZone(ctx, "", strings.NewReader("")); err == nil {
		t.Errorf("Expected error in ImportZone")
	}
}
