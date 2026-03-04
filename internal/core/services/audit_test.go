package services

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

// Mock repository that captures audit logs
type auditMockRepo struct {
	mockRepo // Inherit from existing mock
	logs     []domain.AuditLog
}

func (m *auditMockRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	return m.mockRepo.GetRecords(ctx, name, qType, clientIP)
}

func (m *auditMockRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	return m.mockRepo.GetIPsForName(ctx, name, clientIP)
}

func (m *auditMockRepo) GetZone(ctx context.Context, name string) (*domain.Zone, error) {
	return m.mockRepo.GetZone(ctx, name)
}

func (m *auditMockRepo) ListRecordsForZone(ctx context.Context, zoneID string, tenantID string) ([]domain.Record, error) {
	return m.mockRepo.ListRecordsForZone(ctx, zoneID, tenantID)
}

func (m *auditMockRepo) ListZoneChanges(ctx context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error) {
	return m.mockRepo.ListZoneChanges(ctx, zoneID, fromSerial)
}

func (m *auditMockRepo) GetIXFRChain(ctx context.Context, zoneID string, fromSerial uint32, toSerial uint32) ([]domain.IXFRChunk, error) {
	return m.mockRepo.GetIXFRChain(ctx, zoneID, fromSerial, toSerial)
}

func (m *auditMockRepo) SaveAuditLog(_ context.Context, log *domain.AuditLog) error {
	m.logs = append(m.logs, *log)
	return nil
}

func (m *auditMockRepo) CreateKey(ctx context.Context, key *domain.DNSSECKey) error {
	return m.mockRepo.CreateKey(ctx, key)
}

func (m *auditMockRepo) ListKeysForZone(ctx context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	return m.mockRepo.ListKeysForZone(ctx, zoneID)
}

func (m *auditMockRepo) UpdateKey(ctx context.Context, key *domain.DNSSECKey) error {
	return m.mockRepo.UpdateKey(ctx, key)
}

func (m *auditMockRepo) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	return m.mockRepo.GetAPIKeyByHash(ctx, keyHash)
}

func (m *auditMockRepo) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	return m.mockRepo.CreateAPIKey(ctx, key)
}

func (m *auditMockRepo) ListAPIKeys(ctx context.Context, tenantID string) ([]domain.APIKey, error) {
	return m.mockRepo.ListAPIKeys(ctx, tenantID)
}

func (m *auditMockRepo) DeleteAPIKey(ctx context.Context, tenantID string, id string) error {
	return m.mockRepo.DeleteAPIKey(ctx, tenantID, id)
}

func (m *auditMockRepo) GetRecordsToProbe(ctx context.Context) ([]domain.Record, error) {
	return m.mockRepo.GetRecordsToProbe(ctx)
}

func (m *auditMockRepo) UpdateRecordHealth(ctx context.Context, recordID string, status domain.HealthStatus, errMsg string) error {
	return m.mockRepo.UpdateRecordHealth(ctx, recordID, status, errMsg)
}

func (m *auditMockRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string, tenantID string) error {
	return m.mockRepo.DeleteRecord(ctx, recordID, zoneID, tenantID)
}

func (m *auditMockRepo) DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error {
	return m.mockRepo.DeleteRecordsByNameAndType(ctx, zoneID, name, qType)
}

func (m *auditMockRepo) DeleteRecordsByName(ctx context.Context, zoneID string, name string) error {
	return m.mockRepo.DeleteRecordsByName(ctx, zoneID, name)
}

func (m *auditMockRepo) DeleteRecordsForZone(ctx context.Context, zoneID string) error {
	return m.mockRepo.DeleteRecordsForZone(ctx, zoneID)
}

func (m *auditMockRepo) DeleteRecordSpecific(ctx context.Context, zoneID string, name string, qType domain.RecordType, content string) error {
	return m.mockRepo.DeleteRecordSpecific(ctx, zoneID, name, qType, content)
}

func TestAuditLogCreation(t *testing.T) {
	repo := &auditMockRepo{}
	svc := NewDNSService(repo, nil)

	// 1. Create Zone
	zone := &domain.Zone{Name: "audit.test.", TenantID: "t1"}
	err := svc.CreateZone(context.Background(), zone)
	if err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}

	// Verify Audit Log for Zone Creation
	if len(repo.logs) != 1 {
		t.Fatalf("Expected 1 audit log, got %d", len(repo.logs))
	}
	if repo.logs[0].Action != "CREATE_ZONE" {
		t.Errorf("Expected action CREATE_ZONE, got %s", repo.logs[0].Action)
	}
	if repo.logs[0].ResourceType != "ZONE" {
		t.Errorf("Expected resource type ZONE, got %s", repo.logs[0].ResourceType)
	}

	// 2. Create Record
	record := &domain.Record{Name: "www.audit.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 300}
	err = svc.CreateRecord(context.Background(), record)
	if err != nil {
		t.Fatalf("CreateRecord failed: %v", err)
	}

	// Verify Audit Log for Record Creation
	if len(repo.logs) != 2 {
		t.Fatalf("Expected 2 audit logs, got %d", len(repo.logs))
	}
	if repo.logs[1].Action != "CREATE_RECORD" {
		t.Errorf("Expected action CREATE_RECORD, got %s", repo.logs[1].Action)
	}
	if repo.logs[1].ResourceType != "RECORD" {
		t.Errorf("Expected resource type RECORD, got %s", repo.logs[1].ResourceType)
	}
}
