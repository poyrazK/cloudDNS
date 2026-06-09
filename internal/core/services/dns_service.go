package services

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/master"
)

type dnsService struct {
	repo   ports.DNSRepository
	cache  ports.CacheInvalidator // Used for cross-node invalidation
	logger *slog.Logger
}

// NewDNSService creates a new DNS service with the given repository and cache.
func NewDNSService(repo ports.DNSRepository, cache ports.CacheInvalidator) ports.DNSService {
	return &dnsService{
		repo:   repo,
		cache:  cache,
		logger: slog.Default(),
	}
}

// CreateZone creates a new DNS zone with default SOA and NS records.
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
		TenantID:  zone.TenantID,
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
		TenantID:  zone.TenantID,
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

// CreateRecord creates a new DNS record and invalidates the cache.
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
		if err := s.cache.Invalidate(ctx, record.TenantID, record.Name, record.Type); err != nil {
			s.logger.Warn("failed to invalidate cache after record creation", "name", record.Name, "type", record.Type, "error", err)
		}
	}

	s.audit(ctx, record.TenantID, "CREATE_RECORD", "RECORD", record.ID, fmt.Sprintf("Created %s record for %s", record.Type, record.Name))
	return nil
}

// UpdateRecord updates an existing DNS record.
func (s *dnsService) UpdateRecord(ctx context.Context, record *domain.Record) error {
	record.UpdatedAt = time.Now()

	if record.TTL < 60 {
		record.TTL = 60
	}

	if err := s.repo.UpdateRecord(ctx, record); err != nil {
		return err
	}

	// Invalidate cache across all nodes
	if s.cache != nil {
		if err := s.cache.Invalidate(ctx, record.TenantID, record.Name, record.Type); err != nil {
			s.logger.Warn("failed to invalidate cache after record update", "name", record.Name, "type", record.Type, "error", err)
		}
	}

	s.audit(ctx, record.TenantID, "UPDATE_RECORD", "RECORD", record.ID, fmt.Sprintf("Updated %s record for %s", record.Type, record.Name))
	return nil
}

// audit logs an action to the audit trail via the repository.
func (s *dnsService) audit(ctx context.Context, tenantID, action, resType, resID, details string) {
	logEntry := &domain.AuditLog{
		ID:           uuid.New().String(),
		TenantID:     tenantID,
		Action:       action,
		ResourceType: resType,
		ResourceID:   resID,
		Details:      details,
		CreatedAt:    time.Now(),
	}
	if err := s.repo.SaveAuditLog(ctx, logEntry); err != nil {
		s.logger.Warn("failed to save audit log", "action", action, "resource_id", resID, "error", err)
	}
}

// Resolve looks up DNS records for a name and type, checking direct and wildcard matches.
func (s *dnsService) Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	// 1. Direct Match
	records, err := s.repo.GetRecords(ctx, name, qType, clientIP)
	if err != nil {
		return nil, err
	}

	if len(records) > 0 {
		return s.filterHealthy(records), nil
	}

	// 2. Wildcard Matching (*.domain.com)
	// Build all wildcard candidates upfront to batch into a single query
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	wildcardNames := make([]string, 0, len(labels)-1)
	for i := 0; i < len(labels)-1; i++ {
		wildcardNames = append(wildcardNames, "*."+strings.Join(labels[i+1:], ".")+".")
	}

	// Single batch query instead of N queries
	results, err := s.repo.GetRecordsByNames(ctx, wildcardNames, qType, clientIP)
	if err != nil {
		return nil, err
	}

	// Return first matching wildcard (in label order, same as before)
	for _, wname := range wildcardNames {
		if recs, ok := results[wname]; ok && len(recs) > 0 {
			for j := range recs {
				recs[j].Name = name
			}
			return s.filterHealthy(recs), nil
		}
	}

	return nil, nil
}

// filterHealthy returns only records that are not marked unhealthy, or all records if all are unhealthy.
func (s *dnsService) filterHealthy(records []domain.Record) []domain.Record {
	var healthy []domain.Record
	for _, rec := range records {
		if rec.HealthStatus != domain.HealthStatusUnhealthy {
			healthy = append(healthy, rec)
		}
	}

	// Fallback: If ALL records are unhealthy, return all of them to avoid total blackout.
	if len(healthy) == 0 {
		return records
	}
	return healthy
}

// ListZones returns all zones belonging to a tenant.
func (s *dnsService) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	return s.repo.ListZones(ctx, tenantID)
}

// ListRecordsForZone returns all records in a zone for a given tenant.
func (s *dnsService) ListRecordsForZone(ctx context.Context, zoneID string, tenantID string) ([]domain.Record, error) {
	return s.repo.ListRecordsForZone(ctx, zoneID, tenantID)
}

// DeleteZone deletes a zone and all its records for a tenant.
func (s *dnsService) DeleteZone(ctx context.Context, zoneID string, tenantID string) error {
	if err := s.repo.DeleteZone(ctx, zoneID, tenantID); err != nil {
		return err
	}
	s.audit(ctx, tenantID, "DELETE_ZONE", "ZONE", zoneID, "Deleted zone")
	return nil
}

// DeleteRecord deletes a DNS record and invalidates the cache.
func (s *dnsService) DeleteRecord(ctx context.Context, recordID string, zoneID string, tenantID string) error {
	// Fetch record details to invalidate the cache
	record, err := s.repo.GetRecord(ctx, recordID, zoneID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to fetch record before deletion: %w", err)
	}

	if record != nil && s.cache != nil {
		if errInv := s.cache.Invalidate(ctx, record.TenantID, record.Name, record.Type); errInv != nil {
			s.logger.Warn("failed to invalidate cache before record deletion", "name", record.Name, "type", record.Type, "error", errInv)
		}
	}

	if err := s.repo.DeleteRecord(ctx, recordID, zoneID, tenantID); err != nil {
		return err
	}

	subject := "unknown"
	if record != nil {
		subject = record.Name
	}
	s.audit(ctx, tenantID, "DELETE_RECORD", "RECORD", recordID, fmt.Sprintf("Deleted record for %s", subject))
	return nil
}

// ImportZone parses a zone file and imports it for a tenant.
func (s *dnsService) ImportZone(ctx context.Context, tenantID string, r io.Reader) (*domain.Zone, error) {
	parser := master.New()
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

// GetRecordsToProbeStreaming returns an iterator for records that have health checks configured.
func (s *dnsService) GetRecordsToProbeStreaming(ctx context.Context) (ports.RecordIterator, error) {
	return s.repo.GetRecordsToProbeStreaming(ctx)
}

// UpdateRecordHealth updates the health status and error message for a specific record.
func (s *dnsService) UpdateRecordHealth(ctx context.Context, recordID string, status domain.HealthStatus, errMsg string) error {
	return s.repo.UpdateRecordHealth(ctx, recordID, status, errMsg)
}

// HealthCheck performs dependency health checks (DB, Redis) and returns a map of errors.
func (s *dnsService) HealthCheck(ctx context.Context) map[string]error {
	res := make(map[string]error)

	// Determine appropriate timeout for health check pings.
	// If a deadline was provided, use the remaining time (but at least 100ms).
	// This allows health checks to work even with tight deadlines.
	pingTimeout := 15 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Deadline already passed - skip health checks
			s.logger.Warn("health check skipped: deadline already passed")
			return res
		}
		// Use min of 15s or remaining time, but at least 100ms
		if remaining < pingTimeout {
			if remaining < 100*time.Millisecond {
				s.logger.Warn("health check skipped: insufficient time remaining")
				return res
			}
			pingTimeout = remaining
		}
	}

	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	if s.repo != nil {
		res["postgres"] = s.repo.Ping(pingCtx)
	} else {
		res["postgres"] = nil // Considered healthy if no repo required (test mode)
	}
	if s.cache != nil {
		res["redis"] = s.cache.Ping(pingCtx)
	}
	return res
}
