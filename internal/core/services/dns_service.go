package services

import (
	"context"
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
	
	// Ensure zone name ends with a dot for DNS consistency
	if !strings.HasSuffix(zone.Name, ".") {
		zone.Name += "."
	}

	return s.repo.CreateZone(ctx, zone)
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
