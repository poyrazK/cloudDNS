package services

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

type AnycastManager struct {
	dnsSvc      ports.DNSService
	routing     ports.RoutingEngine
	vipManager  ports.VIPManager
	vip         string
	iface       string
	logger      *slog.Logger
	isAnnounced atomic.Bool
	vipBound    atomic.Bool
}

func NewAnycastManager(
	dnsSvc ports.DNSService,
	routing ports.RoutingEngine,
	vipManager ports.VIPManager,
	vip string,
	iface string,
	logger *slog.Logger,
) *AnycastManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &AnycastManager{
		dnsSvc:     dnsSvc,
		routing:    routing,
		vipManager: vipManager,
		vip:        vip,
		iface:      iface,
		logger:     logger,
	}
}

func (m *AnycastManager) Start(ctx context.Context) {
	m.logger.Info("starting anycast manager", "vip", m.vip, "iface", m.iface)
	
	// Perform immediate check
	m.TriggerCheck(ctx)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("shutting down anycast manager, withdrawing route")
			if err := m.routing.Withdraw(context.Background(), m.vip); err != nil {
				m.logger.Error("failed to withdraw BGP on shutdown", "error", err, "vip", m.vip)
			}
			return
		case <-ticker.C:
			m.TriggerCheck(ctx)
		}
	}
}

// TriggerCheck performs an immediate health check and updates announcement state.
func (m *AnycastManager) TriggerCheck(ctx context.Context) {
	health := m.dnsSvc.HealthCheck(ctx)
	
	healthy := true
	for backend, err := range health {
		if err != nil {
			m.logger.Warn("backend unhealthy", "backend", backend, "error", err)
			healthy = false
		}
	}

	announced := m.isAnnounced.Load()
	if healthy && !announced {
		m.announce(ctx)
	} else if !healthy && announced {
		m.withdraw(ctx)
	}
}

func (m *AnycastManager) announce(ctx context.Context) {
	m.logger.Info("node healthy, initiating anycast announcement")
	
	// 1. Bind VIP if not already bound
	if !m.vipBound.Load() {
		if err := m.vipManager.Bind(ctx, m.vip, m.iface); err != nil {
			m.logger.Error("failed to bind VIP", "error", err)
			return
		}
		m.vipBound.Store(true)
	}

	// 2. Announce BGP
	if err := m.routing.Announce(ctx, m.vip); err != nil {
		m.logger.Error("failed to announce BGP", "error", err)
		return
	}

	m.isAnnounced.Store(true)
}

func (m *AnycastManager) withdraw(ctx context.Context) {
	m.logger.Warn("node unhealthy, withdrawing anycast announcement")
	
	if err := m.routing.Withdraw(ctx, m.vip); err != nil {
		m.logger.Error("failed to withdraw BGP", "error", err)
		return // Do not clear isAnnounced flag if withdrawal failed
	}

	m.isAnnounced.Store(false)
	// We keep the VIP bound to the interface for local connectivity/checks
}
