package ports

import (
	"context"
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
	SaveAuditLog(ctx context.Context, log *domain.AuditLog) error
	GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error)
	Ping(ctx context.Context) error
}

type DNSService interface {
	CreateZone(ctx context.Context, zone *domain.Zone) error
	CreateRecord(ctx context.Context, record *domain.Record) error
	Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error)
	ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error)
	DeleteZone(ctx context.Context, zoneID string, tenantID string) error
	DeleteRecord(ctx context.Context, recordID string, zoneID string) error
	HealthCheck(ctx context.Context) error
}
