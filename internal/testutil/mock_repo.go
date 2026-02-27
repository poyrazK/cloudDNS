package testutil

import (
	"context"
	"io"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/stretchr/testify/mock"
)

type MockRepo struct {
	mock.Mock
}

func (m *MockRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	args := m.Called(name, qType, clientIP)
	return args.Get(0).([]domain.Record), args.Error(1)
}

func (m *MockRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	args := m.Called(name, clientIP)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockRepo) GetZone(ctx context.Context, name string) (*domain.Zone, error) {
	args := m.Called(name)
	return args.Get(0).(*domain.Zone), args.Error(1)
}

func (m *MockRepo) GetRecord(ctx context.Context, id string, zoneID string) (*domain.Record, error) {
	args := m.Called(id, zoneID)
	return args.Get(0).(*domain.Record), args.Error(1)
}

func (m *MockRepo) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	args := m.Called(zoneID)
	return args.Get(0).([]domain.Record), args.Error(1)
}

func (m *MockRepo) CreateZone(ctx context.Context, zone *domain.Zone) error {
	args := m.Called(zone)
	return args.Error(0)
}

func (m *MockRepo) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error {
	args := m.Called(zone, records)
	return args.Error(0)
}

func (m *MockRepo) CreateRecord(ctx context.Context, record *domain.Record) error {
	args := m.Called(record)
	return args.Error(0)
}

func (m *MockRepo) BatchCreateRecords(ctx context.Context, records []domain.Record) error {
	args := m.Called(records)
	return args.Error(0)
}

func (m *MockRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.Zone), args.Error(1)
}

func (m *MockRepo) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	args := m.Called(zoneID, tenantID)
	return args.Error(0)
}

func (m *MockRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string) error {
	args := m.Called(recordID, zoneID)
	return args.Error(0)
}

func (m *MockRepo) DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error {
	args := m.Called(zoneID, name, qType)
	return args.Error(0)
}

func (m *MockRepo) DeleteRecordsByName(ctx context.Context, zoneID string, name string) error {
	args := m.Called(zoneID, name)
	return args.Error(0)
}

func (m *MockRepo) DeleteRecordSpecific(ctx context.Context, zoneID string, name string, qType domain.RecordType, content string) error {
	args := m.Called(zoneID, name, qType, content)
	return args.Error(0)
}

func (m *MockRepo) RecordZoneChange(ctx context.Context, change *domain.ZoneChange) error {
	args := m.Called(change)
	return args.Error(0)
}

func (m *MockRepo) ListZoneChanges(ctx context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error) {
	args := m.Called(zoneID, fromSerial)
	return args.Get(0).([]domain.ZoneChange), args.Error(1)
}

func (m *MockRepo) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error {
	args := m.Called(log)
	return args.Error(0)
}

func (m *MockRepo) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

func (m *MockRepo) Ping(ctx context.Context) error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockRepo) CreateKey(ctx context.Context, key *domain.DNSSECKey) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockRepo) ListKeysForZone(ctx context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	args := m.Called(zoneID)
	return args.Get(0).([]domain.DNSSECKey), args.Error(1)
}

func (m *MockRepo) UpdateKey(ctx context.Context, key *domain.DNSSECKey) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockRepo) GetAPIKeyByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	args := m.Called(keyHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.APIKey), args.Error(1)
}

func (m *MockRepo) CreateAPIKey(ctx context.Context, key *domain.APIKey) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockRepo) ListAPIKeys(ctx context.Context, tenantID string) ([]domain.APIKey, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.APIKey), args.Error(1)
}

func (m *MockRepo) DeleteAPIKey(ctx context.Context, id string) error {
	args := m.Called(id)
	return args.Error(0)
}

type MockDNSService struct {
	mock.Mock
}

func (m *MockDNSService) CreateZone(ctx context.Context, zone *domain.Zone) error {
	args := m.Called(zone)
	return args.Error(0)
}

func (m *MockDNSService) CreateRecord(ctx context.Context, record *domain.Record) error {
	args := m.Called(record)
	return args.Error(0)
}

func (m *MockDNSService) Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	args := m.Called(name, qType, clientIP)
	return args.Get(0).([]domain.Record), args.Error(1)
}

func (m *MockDNSService) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.Zone), args.Error(1)
}

func (m *MockDNSService) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	args := m.Called(zoneID)
	return args.Get(0).([]domain.Record), args.Error(1)
}

func (m *MockDNSService) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	args := m.Called(zoneID, tenantID)
	return args.Error(0)
}

func (m *MockDNSService) DeleteRecord(ctx context.Context, recordID string, zoneID string) error {
	args := m.Called(recordID, zoneID)
	return args.Error(0)
}

func (m *MockDNSService) ImportZone(ctx context.Context, tenantID string, r io.Reader) (*domain.Zone, error) {
	args := m.Called(tenantID, r)
	return args.Get(0).(*domain.Zone), args.Error(1)
}

func (m *MockDNSService) ListAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

func (m *MockDNSService) HealthCheck(ctx context.Context) map[string]error {
	args := m.Called()
	return args.Get(0).(map[string]error)
}
