package ports

import (
	"context"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type DNSRepository interface {
	GetRecords(ctx context.Context, name string, qType domain.RecordType) ([]domain.Record, error)
}
