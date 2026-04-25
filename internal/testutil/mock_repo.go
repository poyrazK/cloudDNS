// Package testutil provides mock implementations for testing DNS components.
package testutil

import (
	"context"
	"io"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/stretchr/testify/mock"
)

// MockRepo implements ports.DNSRepository for testing.
type MockRepo struct {
	mock.Mock
}

// GetRecords implements ports.DNSRepository for testing.
func (m *MockRepo) GetRecords(_ context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	args := m.Called(name, qType, clientIP)
	return args.Get(0).([]domain.Record), args.Error(1)
}

// GetIPsForName implements ports.DNSRepository for testing.
func (m *MockRepo) GetIPsForName(_ context.Context, name string, clientIP string) ([]string, error) {
	args := m.Called(name, clientIP)
	return args.Get(0).([]string), args.Error(1)
}

// GetZone implements ports.DNSRepository for testing.
func (m *MockRepo) GetZone(_ context.Context, name string) (*domain.Zone, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Zone), args.Error(1)
}

// GetZoneLongestMatch implements ports.DNSRepository for testing.
func (m *MockRepo) GetZoneLongestMatch(_ context.Context, qName string) (*domain.Zone, error) {
	args := m.Called(qName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Zone), args.Error(1)
}

// GetRecord implements ports.DNSRepository for testing.
func (m *MockRepo) GetRecord(_ context.Context, id string, zoneID string, tenantID string) (*domain.Record, error) {
	args := m.Called(id, zoneID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Record), args.Error(1)
}

// ListRecordsForZone implements ports.DNSRepository for testing.
func (m *MockRepo) ListRecordsForZone(_ context.Context, zoneID string, tenantID string) ([]domain.Record, error) {
	args := m.Called(zoneID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Record), args.Error(1)
}

// ListRecordsForZoneStreaming implements ports.DNSRepository for testing.
func (m *MockRepo) ListRecordsForZoneStreaming(_ context.Context, zoneID string, tenantID string) (ports.RecordIterator, error) {
	args := m.Called(zoneID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(ports.RecordIterator), args.Error(1)
}

// CreateZone implements ports.DNSRepository for testing.
func (m *MockRepo) CreateZone(_ context.Context, zone *domain.Zone) error {
	args := m.Called(zone)
	return args.Error(0)
}

// CreateZoneWithRecords implements ports.DNSRepository for testing.
func (m *MockRepo) CreateZoneWithRecords(_ context.Context, zone *domain.Zone, records []domain.Record) error {
	args := m.Called(zone, records)
	return args.Error(0)
}

// CreateRecord implements ports.DNSRepository for testing.
func (m *MockRepo) CreateRecord(_ context.Context, record *domain.Record) error {
	args := m.Called(record)
	return args.Error(0)
}

// BatchCreateRecords implements ports.DNSRepository for testing.
func (m *MockRepo) BatchCreateRecords(_ context.Context, records []domain.Record) error {
	args := m.Called(records)
	return args.Error(0)
}

// ListZones implements ports.DNSRepository for testing.
func (m *MockRepo) ListZones(_ context.Context, tenantID string) ([]domain.Zone, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.Zone), args.Error(1)
}

// DeleteZone implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteZone(_ context.Context, zoneID string, tenantID string) error {
	args := m.Called(zoneID, tenantID)
	return args.Error(0)
}

// DeleteRecord implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteRecord(_ context.Context, recordID string, zoneID string, tenantID string) error {
	args := m.Called(recordID, zoneID, tenantID)
	return args.Error(0)
}

// DeleteRecordsByNameAndType implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteRecordsByNameAndType(_ context.Context, zoneID string, name string, qType domain.RecordType) error {
	args := m.Called(zoneID, name, qType)
	return args.Error(0)
}

// DeleteRecordsByName implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteRecordsByName(_ context.Context, zoneID string, name string) error {
	args := m.Called(zoneID, name)
	return args.Error(0)
}

// DeleteRecordsForZone implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteRecordsForZone(_ context.Context, zoneID string) error {
	args := m.Called(zoneID)
	return args.Error(0)
}

// DeleteRecordSpecific implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteRecordSpecific(_ context.Context, zoneID string, name string, qType domain.RecordType, content string) error {
	args := m.Called(zoneID, name, qType, content)
	return args.Error(0)
}

// RecordZoneChange implements ports.DNSRepository for testing.
func (m *MockRepo) RecordZoneChange(_ context.Context, change *domain.ZoneChange) error {
	args := m.Called(change)
	return args.Error(0)
}

// ListZoneChanges implements ports.DNSRepository for testing.
func (m *MockRepo) ListZoneChanges(_ context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error) {
	args := m.Called(zoneID, fromSerial)
	return args.Get(0).([]domain.ZoneChange), args.Error(1)
}

// GetIXFRChain implements ports.DNSRepository for testing.
func (m *MockRepo) GetIXFRChain(_ context.Context, zoneID string, fromSerial uint32, toSerial uint32) ([]domain.IXFRChunk, error) {
	args := m.Called(zoneID, fromSerial, toSerial)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.IXFRChunk), args.Error(1)
}

// SaveAuditLog implements ports.DNSRepository for testing.
func (m *MockRepo) SaveAuditLog(_ context.Context, log *domain.AuditLog) error {
	args := m.Called(log)
	return args.Error(0)
}

// GetAuditLogs implements ports.DNSRepository for testing.
func (m *MockRepo) GetAuditLogs(_ context.Context, tenantID string) ([]domain.AuditLog, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

// Ping implements ports.DNSRepository for testing.
func (m *MockRepo) Ping(_ context.Context) error {
	args := m.Called()
	return args.Error(0)
}

// ApplyZoneUpdate implements ports.DNSRepository for testing.
func (m *MockRepo) ApplyZoneUpdate(_ context.Context, zoneID string, operations []domain.UpdateOperation, changes []domain.ZoneChange) (uint32, error) {
	args := m.Called(zoneID, operations, changes)
	return args.Get(0).(uint32), args.Error(1)
}

// CreateKey implements ports.DNSRepository for testing.
func (m *MockRepo) CreateKey(_ context.Context, key *domain.DNSSECKey) error {
	args := m.Called(key)
	return args.Error(0)
}

// ListKeysForZone implements ports.DNSRepository for testing.
func (m *MockRepo) ListKeysForZone(_ context.Context, zoneID string) ([]domain.DNSSECKey, error) {
	args := m.Called(zoneID)
	return args.Get(0).([]domain.DNSSECKey), args.Error(1)
}

// UpdateKey implements ports.DNSRepository for testing.
func (m *MockRepo) UpdateKey(_ context.Context, key *domain.DNSSECKey) error {
	args := m.Called(key)
	return args.Error(0)
}

// GetDNSKEYs implements ports.DNSRepository for testing.
func (m *MockRepo) GetDNSKEYs(_ context.Context, zoneName string) ([]domain.Record, error) {
	args := m.Called(zoneName)
	return args.Get(0).([]domain.Record), args.Error(1)
}

// GetAPIKeyByHash implements ports.DNSRepository for testing.
func (m *MockRepo) GetAPIKeyByHash(_ context.Context, keyHash string) (*domain.APIKey, error) {
	args := m.Called(keyHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.APIKey), args.Error(1)
}

// CreateAPIKey implements ports.DNSRepository for testing.
func (m *MockRepo) CreateAPIKey(_ context.Context, key *domain.APIKey) error {
	args := m.Called(key)
	return args.Error(0)
}

// ListAPIKeys implements ports.DNSRepository for testing.
func (m *MockRepo) ListAPIKeys(_ context.Context, tenantID string) ([]domain.APIKey, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.APIKey), args.Error(1)
}

// DeleteAPIKey implements ports.DNSRepository for testing.
func (m *MockRepo) DeleteAPIKey(_ context.Context, tenantID string, id string) error {
	args := m.Called(tenantID, id)
	return args.Error(0)
}

// UpdateRecordHealth implements ports.DNSRepository for testing.
func (m *MockRepo) UpdateRecordHealth(ctx context.Context, recordID string, status domain.HealthStatus, errMsg string) error {
	args := m.Called(ctx, recordID, status, errMsg)
	return args.Error(0)
}

// GetRecordsToProbe implements ports.DNSRepository for testing.
func (m *MockRepo) GetRecordsToProbe(_ context.Context) ([]domain.Record, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Record), args.Error(1)
}

// MockDNSService implements ports.DNSService for testing.
type MockDNSService struct {
	mock.Mock
}

// CreateZone implements ports.DNSService for testing.
func (m *MockDNSService) CreateZone(_ context.Context, zone *domain.Zone) error {
	args := m.Called(zone)
	return args.Error(0)
}

// CreateRecord implements ports.DNSService for testing.
func (m *MockDNSService) CreateRecord(_ context.Context, record *domain.Record) error {
	args := m.Called(record)
	return args.Error(0)
}

// Resolve implements ports.DNSService for testing.
func (m *MockDNSService) Resolve(_ context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	args := m.Called(name, qType, clientIP)
	return args.Get(0).([]domain.Record), args.Error(1)
}

// GetRecordsToProbe implements ports.DNSService for testing.
func (m *MockDNSService) GetRecordsToProbe(_ context.Context) ([]domain.Record, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Record), args.Error(1)
}

// UpdateRecordHealth implements ports.DNSService for testing.
func (m *MockDNSService) UpdateRecordHealth(_ context.Context, recordID string, status domain.HealthStatus, errMsg string) error {
	args := m.Called(recordID, status, errMsg)
	return args.Error(0)
}

// ListZones implements ports.DNSService for testing.
func (m *MockDNSService) ListZones(_ context.Context, tenantID string) ([]domain.Zone, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.Zone), args.Error(1)
}

// ListRecordsForZone implements ports.DNSService for testing.
func (m *MockDNSService) ListRecordsForZone(_ context.Context, zoneID string, tenantID string) ([]domain.Record, error) {
	args := m.Called(zoneID, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Record), args.Error(1)
}

// DeleteZone implements ports.DNSService for testing.
func (m *MockDNSService) DeleteZone(_ context.Context, zoneID string, tenantID string) error {
	args := m.Called(zoneID, tenantID)
	return args.Error(0)
}

// DeleteRecord implements ports.DNSService for testing.
func (m *MockDNSService) DeleteRecord(_ context.Context, recordID string, zoneID string, tenantID string) error {
	args := m.Called(recordID, zoneID, tenantID)
	return args.Error(0)
}

// ImportZone implements ports.DNSService for testing.
func (m *MockDNSService) ImportZone(_ context.Context, tenantID string, r io.Reader) (*domain.Zone, error) {
	args := m.Called(tenantID, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Zone), args.Error(1)
}

// ListAuditLogs implements ports.DNSService for testing.
func (m *MockDNSService) ListAuditLogs(_ context.Context, tenantID string) ([]domain.AuditLog, error) {
	args := m.Called(tenantID)
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

// HealthCheck implements ports.DNSService for testing.
func (m *MockDNSService) HealthCheck(_ context.Context) map[string]error {
	args := m.Called()
	return args.Get(0).(map[string]error)
}
