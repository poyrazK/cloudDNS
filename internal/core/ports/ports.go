package ports

import (
	"context"
	"io"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type DNSRepository interface {
	GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error)
	GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error)
	GetZone(ctx context.Context, name string) (*domain.Zone, error)
	ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error)
	CreateZone(ctx context.Context, zone *domain.Zone) error
	CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error
	CreateRecord(ctx context.Context, record *domain.Record) error
	ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error)
	DeleteZone(ctx context.Context, zoneID string, tenantID string) error
	DeleteRecord(ctx context.Context, recordID string, zoneID string) error
	DeleteRecordsByNameAndType(ctx context.Context, zoneID string, name string, qType domain.RecordType) error
	DeleteRecordsByName(ctx context.Context, zoneID string, name string) error
	DeleteRecordSpecific(ctx context.Context, zoneID string, name string, qType domain.RecordType, content string) error
	RecordZoneChange(ctx context.Context, change *domain.ZoneChange) error
	ListZoneChanges(ctx context.Context, zoneID string, fromSerial uint32) ([]domain.ZoneChange, error)
	SaveAuditLog(ctx context.Context, log *domain.AuditLog) error
	GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error)
	Ping(ctx context.Context) error

	// DNSSEC Key Management
	CreateKey(ctx context.Context, key *domain.DNSSECKey) error
	ListKeysForZone(ctx context.Context, zoneID string) ([]domain.DNSSECKey, error)
	UpdateKey(ctx context.Context, key *domain.DNSSECKey) error
}

type DNSService interface {
	CreateZone(ctx context.Context, zone *domain.Zone) error
	CreateRecord(ctx context.Context, record *domain.Record) error
	Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error)
	ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error)
	ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error)
	DeleteZone(ctx context.Context, zoneID string, tenantID string) error
	DeleteRecord(ctx context.Context, recordID string, zoneID string) error
	ImportZone(ctx context.Context, tenantID string, r io.Reader) (*domain.Zone, error)
	HealthCheck(ctx context.Context) error
}
