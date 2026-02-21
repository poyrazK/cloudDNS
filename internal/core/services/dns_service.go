package services

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
)

type dnsService struct {
	repo  ports.DNSRepository
	cache ports.CacheInvalidator // Used for cross-node invalidation
}

func NewDNSService(repo ports.DNSRepository, cache ports.CacheInvalidator) ports.DNSService {
	return &dnsService{repo: repo, cache: cache}
}

func (s *dnsService) CreateZone(ctx context.Context, zone *domain.Zone) error {
	zone.ID = uuid.New().String()
	zone.CreatedAt = time.Now()
	zone.UpdatedAt = time.Now()

	// Ensure zone name ends with a dot
	if !strings.HasSuffix(zone.Name, ".") {
		zone.Name += "."
	}

	// 1. Create Default SOA Record
	soaContent := fmt.Sprintf("ns1.clouddns.io. admin.clouddns.io. %s 3600 600 1209600 300",
		time.Now().Format("2006010201"))
	
	soaRecord := &domain.Record{
		ID:        uuid.New().String(),
		ZoneID:    zone.ID,
		Name:      zone.Name,
		Type:      domain.TypeSOA,
		Content:   soaContent,
		TTL:       3600,
		CreatedAt: zone.CreatedAt,
		UpdatedAt: zone.UpdatedAt,
	}

	// 2. Create Default NS Record
	nsRecord := &domain.Record{
		ID:        uuid.New().String(),
		ZoneID:    zone.ID,
		Name:      zone.Name,
		Type:      domain.TypeNS,
		Content:   "ns1.clouddns.io.",
		TTL:       3600,
		CreatedAt: zone.CreatedAt,
		UpdatedAt: zone.UpdatedAt,
	}

	if err := s.repo.CreateZoneWithRecords(ctx, zone, []domain.Record{*soaRecord, *nsRecord}); err != nil {
		return err
	}

	// 3. Audit Log
	s.audit(ctx, zone.TenantID, "CREATE_ZONE", "ZONE", zone.ID, fmt.Sprintf("Created zone %s", zone.Name))
	return nil
}

func (s *dnsService) CreateRecord(ctx context.Context, record *domain.Record) error {
	record.ID = uuid.New().String()
	record.CreatedAt = time.Now()
	record.UpdatedAt = time.Now()

	if record.TTL < 60 {
		record.TTL = 60
	}

	if err := s.repo.CreateRecord(ctx, record); err != nil {
		return err
	}

	// Invalidate cache across all nodes
	if s.cache != nil {
		_ = s.cache.Invalidate(ctx, record.Name, record.Type)
	}

	s.audit(ctx, "unknown", "CREATE_RECORD", "RECORD", record.ID, fmt.Sprintf("Created %s record for %s", record.Type, record.Name))
	return nil
}

func (s *dnsService) audit(ctx context.Context, tenantID, action, resType, resID, details string) {
	log := &domain.AuditLog{
		ID:           uuid.New().String(),
		TenantID:     tenantID,
		Action:       action,
		ResourceType: resType,
		ResourceID:   resID,
		Details:      details,
		CreatedAt:    time.Now(),
	}
	_ = s.repo.SaveAuditLog(ctx, log) // Fire and forget audit for now
}

func (s *dnsService) Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	// 1. Direct Match
	records, err := s.repo.GetRecords(ctx, name, qType, clientIP)
	if err != nil {
		return nil, err
	}
	if len(records) > 0 {
		return records, nil
	}

	// 2. Wildcard Matching (*.domain.com)
	// We iteratively strip labels from the left and replace with '*'
	// e.g. "a.b.example.com." -> "*.b.example.com." -> "*.example.com." -> "*.com."
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		wildcardName := "*." + strings.Join(labels[i+1:], ".") + "."
		
		wildcardRecords, err := s.repo.GetRecords(ctx, wildcardName, qType, clientIP)
		if err != nil {
			return nil, err
		}
		if len(wildcardRecords) > 0 {
			// Rewrite wildcard name to the requested name for the response
			for j := range wildcardRecords {
				wildcardRecords[j].Name = name
			}
			return wildcardRecords, nil
		}
	}

	return nil, nil
}

func (s *dnsService) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	return s.repo.ListZones(ctx, tenantID)
}

func (s *dnsService) ListRecordsForZone(ctx context.Context, zoneID string) ([]domain.Record, error) {
	return s.repo.ListRecordsForZone(ctx, zoneID)
}

func (s *dnsService) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	if err := s.repo.DeleteZone(ctx, zoneID, tenantID); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "DELETE_ZONE", "ZONE", zoneID, "Deleted zone")
	return nil
}

func (s *dnsService) DeleteRecord(ctx context.Context, recordID string, zoneID string) error {
	// We need record details to invalidate the cache
	// For simplicity in this implementation, we might just flush or require more context.
	// RFC 2136 handled this by name/type. For REST API, we'll try to find the record first.
	
	// TODO: Fetch record details before delete to call s.cache.Invalidate(ctx, name, type)
	
	if err := s.repo.DeleteRecord(ctx, recordID, zoneID); err != nil {
		return err
	}
	s.audit(ctx, "unknown", "DELETE_RECORD", "RECORD", recordID, "Deleted record")
	return nil
}

func (s *dnsService) ImportZone(ctx context.Context, tenantID string, r io.Reader) (*domain.Zone, error) {
	parser := master.NewMasterParser()
	data, err := parser.Parse(r)
	if err != nil {
		return nil, err
	}

	zone := &data.Zone
	zone.ID = uuid.New().String()
	zone.TenantID = tenantID
	zone.CreatedAt = time.Now()
	zone.UpdatedAt = time.Now()

	// Prepare records
	for i := range data.Records {
		data.Records[i].ID = uuid.New().String()
		data.Records[i].ZoneID = zone.ID
		data.Records[i].CreatedAt = zone.CreatedAt
		data.Records[i].UpdatedAt = zone.UpdatedAt
	}

	if err := s.repo.CreateZoneWithRecords(ctx, zone, data.Records); err != nil {
		return nil, err
	}

	s.audit(ctx, tenantID, "IMPORT_ZONE", "ZONE", zone.ID, fmt.Sprintf("Imported zone %s with %d records", zone.Name, len(data.Records)))
	return zone, nil
}

// ListAuditLogs retrieves audit trail entries for a specific tenant.
func (s *dnsService) ListAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) {
	return s.repo.GetAuditLogs(ctx, tenantID)
}

func (s *dnsService) HealthCheck(ctx context.Context) map[string]error {
	res := make(map[string]error)
	res["postgres"] = s.repo.Ping(ctx)
	if s.cache != nil {
		// We need to type assert to check Ping if it's a RedisCache
		if pinger, ok := s.cache.(interface{ Ping(context.Context) error }); ok {
			res["redis"] = pinger.Ping(ctx)
		}
	}
	return res
}
