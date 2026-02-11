package services

import (
	"context"
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

func TestCreateZone(t *testing.T) {
	repo := &mockRepo{}
	svc := NewDNSService(repo)

	zone := &domain.Zone{Name: "example.com", TenantID: "t1"}
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
