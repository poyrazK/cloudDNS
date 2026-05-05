package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
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

// HealthMonitorOptions configures optional health monitor behavior.
type HealthMonitorOptions struct {
	InsecureSkipVerify bool
}

// NewHealthMonitor creates a new HealthMonitor with a default HTTP client.
func NewHealthMonitor(repo ports.DNSRepository, logger *slog.Logger, opts *HealthMonitorOptions) *HealthMonitor {
	client := &http.Client{Timeout: 5 * time.Second}
	if opts != nil && opts.InsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return &HealthMonitor{
		repo:   repo,
		logger: logger,
		client: client,
	}
}

const maxProbeWorkers = 10

// Start runs the health monitoring loop at the specified interval until the context is canceled.
func (m *HealthMonitor) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
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
	const batchSize = 100

	iter, err := m.repo.GetRecordsToProbeStreaming(ctx)
	if err != nil {
		m.logger.Error("failed to create records iterator", "error", err)
		return
	}
	defer func() {
		if closeErr := iter.Close(); closeErr != nil {
			m.logger.Error("failed to close records iterator", "error", closeErr)
		}
	}()

	batch := make([]domain.Record, 0, batchSize)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxProbeWorkers)

	for {
		// Check context cancellation at start of each iteration
		select {
		case <-ctx.Done():
			wg.Wait() // Wait for in-flight probes to complete
			return
		default:
		}

		// Fill batch
		for len(batch) < batchSize && iter.Next() {
			batch = append(batch, iter.Record())
		}

		if iter.Err() != nil {
			m.logger.Error("iterator error during health check fetch", "error", iter.Err())
			break
		}

		if len(batch) == 0 {
			break
		}

		for _, rec := range batch {
			// Acquire semaphore slot before spawning goroutine
			semaphore <- struct{}{}
			wg.Add(1)
			go func(r domain.Record) {
				defer wg.Done()
				defer func() { <-semaphore }()
				m.probeRecord(ctx, r)
			}(rec)
		}
		wg.Wait()

		batch = batch[:0]
	}
}

func (m *HealthMonitor) probeRecord(ctx context.Context, rec domain.Record) {
	var status domain.HealthStatus
	var errMsg string

	switch rec.HealthCheckType {
	case domain.HealthCheckHTTP:
		status, errMsg = m.probeHTTP(ctx, rec.HealthCheckTarget)
	case domain.HealthCheckTCP:
		status, errMsg = m.probeTCP(ctx, rec.HealthCheckTarget)
	default:
		return
	}

	if err := m.repo.UpdateRecordHealth(ctx, rec.ID, status, errMsg); err != nil {
		m.logger.Error("failed to update record health", "record_id", rec.ID, "error", err)
	}
}

func (m *HealthMonitor) probeHTTP(ctx context.Context, target string) (domain.HealthStatus, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return domain.HealthStatusUnhealthy, err.Error()
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return domain.HealthStatusUnhealthy, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return domain.HealthStatusHealthy, ""
	}

	return domain.HealthStatusUnhealthy, fmt.Sprintf("HTTP status: %d", resp.StatusCode)
}

func (m *HealthMonitor) probeTCP(ctx context.Context, target string) (domain.HealthStatus, string) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return domain.HealthStatusUnhealthy, err.Error()
	}
	defer func() { _ = conn.Close() }()

	return domain.HealthStatusHealthy, ""
}
