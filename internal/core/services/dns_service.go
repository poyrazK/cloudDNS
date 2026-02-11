package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

type dnsService struct {
	repo ports.DNSRepository
}

func NewDNSService(repo ports.DNSRepository) ports.DNSService {
	return &dnsService{repo: repo}
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
	// Format: "ns1.clouddns.io. admin.clouddns.io. 2024021101 3600 600 1209600 300"
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

	// We need a repository method that handles this atomically
	return s.repo.CreateZoneWithRecords(ctx, zone, []domain.Record{*soaRecord, *nsRecord})
}

func (s *dnsService) CreateRecord(ctx context.Context, record *domain.Record) error {
	record.ID = uuid.New().String()
	record.CreatedAt = time.Now()
	record.UpdatedAt = time.Now()

	// Basic TTL validation
	if record.TTL < 60 {
		record.TTL = 60
	}

	return s.repo.CreateRecord(ctx, record)
}

func (s *dnsService) Resolve(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	return s.repo.GetRecords(ctx, name, qType, clientIP)
}

func (s *dnsService) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) {
	return s.repo.ListZones(ctx, tenantID)
}
