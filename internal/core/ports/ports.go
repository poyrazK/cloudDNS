// Package ports defines the input and output ports for the hexagonal architecture.
package ports

import (
	"context"
	"io"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

// DNSRepository defines the interface for DNS data persistence.
type DNSRepository interface {
	GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error)
	GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error)
	GetZone(ctx context.Context, name string) (*domain.Zone, error)
	GetRecord(ctx context.Context, id string, zoneID string) (*domain.Record, error)
	ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error)
	CreateZone(ctx context.Context, zone *domain.Zone) error
	CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error
	CreateRecord(ctx context.Context, record *domain.Record) error
	BatchCreateRecords(ctx context.Context, records []domain.Record) error
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

// DNSService defines the interface for core DNS business logic.
type DNSService interface {
	CreateZone(ctx context.Context, zone *domain.Zone) error
	CreateRecord(ctx context.Context, record *domain.Record) error
	Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error)
	ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error)
	ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error)
	DeleteZone(ctx context.Context, zoneID string, tenantID string) error
	DeleteRecord(ctx context.Context, recordID string, zoneID string) error
	ImportZone(ctx context.Context, tenantID string, r io.Reader) (*domain.Zone, error)
	ListAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error)
	HealthCheck(ctx context.Context) map[string]error
}

// CacheInvalidator defines the interface for triggering cross-node cache invalidation.
type CacheInvalidator interface {
	Invalidate(ctx context.Context, name string, qType domain.RecordType) error
	Ping(ctx context.Context) error
}

// RoutingEngine defines the interface for BGP route advertisement.
type RoutingEngine interface {
	Start(ctx context.Context, localASN, peerASN uint32, peerIP string) error
	Announce(ctx context.Context, vip string) error
	Withdraw(ctx context.Context, vip string) error
	Stop() error
}

// VIPManager defines the interface for managing the Anycast VIP on the local system.
type VIPManager interface {
	Bind(ctx context.Context, vip, iface string) error
	Unbind(ctx context.Context, vip, iface string) error
}
