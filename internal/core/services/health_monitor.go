package services

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

// HealthMonitor manages background health checks for DNS records.
type HealthMonitor struct {
	repo   ports.DNSRepository
	logger *slog.Logger
	client *http.Client
}

// NewHealthMonitor creates a new HealthMonitor.
func NewHealthMonitor(repo ports.DNSRepository, logger *slog.Logger) *HealthMonitor {
	return &HealthMonitor{
		repo:   repo,
		logger: logger,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start runs the health monitoring loop.
func (m *HealthMonitor) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.logger.Info("starting health monitor", "interval", interval)

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("stopping health monitor")
			return
		case <-ticker.C:
			m.runChecks(ctx)
		}
	}
}

func (m *HealthMonitor) runChecks(ctx context.Context) {
	records, err := m.repo.GetRecordsToProbe(ctx)
	if err != nil {
		m.logger.Error("failed to fetch records to probe", "error", err)
		return
	}

	for _, rec := range records {
		go m.probeRecord(ctx, rec)
	}
}

func (m *HealthMonitor) probeRecord(ctx context.Context, rec domain.Record) {
	var status domain.HealthStatus
	var errMsg string

	switch rec.HealthCheckType {
	case domain.HealthCheckHTTP:
		status, errMsg = m.probeHTTP(rec.HealthCheckTarget)
	case domain.HealthCheckTCP:
		status, errMsg = m.probeTCP(rec.HealthCheckTarget)
	default:
		return
	}

	if err := m.repo.UpdateRecordHealth(ctx, rec.ID, status, errMsg); err != nil {
		m.logger.Error("failed to update record health", "record_id", rec.ID, "error", err)
	}
}

func (m *HealthMonitor) probeHTTP(target string) (domain.HealthStatus, string) {
	resp, err := m.client.Get(target)
	if err != nil {
		return domain.HealthStatusUnhealthy, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.HealthStatusHealthy, ""
	}

	return domain.HealthStatusUnhealthy, fmt.Sprintf("HTTP status: %d", resp.StatusCode)
}

func (m *HealthMonitor) probeTCP(target string) (domain.HealthStatus, string) {
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return domain.HealthStatusUnhealthy, err.Error()
	}
	defer conn.Close()

	return domain.HealthStatusHealthy, ""
}
