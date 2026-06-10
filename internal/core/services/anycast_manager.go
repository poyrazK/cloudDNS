package services

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

// AnycastManager manages anycast VIP assignment and BGP routing.
type AnycastManager struct {
	dnsSvc      ports.DNSService
	routing     ports.RoutingEngine
	vipManager  ports.VIPManager
	vip         string
	iface       string
	logger      *slog.Logger
	isAnnounced atomic.Bool
	vipBound    atomic.Bool
	mu          sync.Mutex // protects state transitions for check-then-act

	// Debounce: health state transitions are delayed to avoid flapping
	debounceDuration time.Duration
	debounceTimer    *time.Timer
	debounceCh       chan struct{} // signals when debounce timer fires
}

// NewAnycastManager creates a new AnycastManager for the given VIP and routing engine.
// debounceDuration sets the minimum time a health state must be stable before acting
// on the transition, preventing VIP flapping under unstable health checks.
func NewAnycastManager(
	dnsSvc ports.DNSService,
	routing ports.RoutingEngine,
	vipManager ports.VIPManager,
	vip string,
	iface string,
	logger *slog.Logger,
	debounceDuration time.Duration,
) *AnycastManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &AnycastManager{
		dnsSvc:            dnsSvc,
		routing:           routing,
		vipManager:        vipManager,
		vip:               vip,
		iface:             iface,
		logger:            logger,
		debounceDuration:  debounceDuration,
		debounceCh:        make(chan struct{}, 1),
	}
}

// Start begins the anycast manager background worker.
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
			if m.debounceTimer != nil {
				m.debounceTimer.Stop()
			}
			if err := m.routing.Withdraw(ctx, m.vip); err != nil {
				m.logger.Error("failed to withdraw BGP on shutdown", "error", err, "vip", m.vip)
			}
			metrics.BGPAnnounced.Set(0)
			return
		case <-ticker.C:
			m.TriggerCheck(ctx)
		case <-m.debounceCh:
			// Debounce timer fired; perform announce if still healthy
			m.mu.Lock()
			if !m.isAnnounced.Load() {
				m.announceLocked(ctx)
			}
			m.mu.Unlock()
		}
	}
}

// TriggerCheck performs an immediate health check and updates announcement state.
// State transitions are debounced to prevent VIP flapping under unstable health.
func (m *AnycastManager) TriggerCheck(ctx context.Context) {
	health := m.dnsSvc.HealthCheck(ctx)

	healthy := true
	for backend, err := range health {
		if err != nil {
			m.logger.Warn("backend unhealthy", "backend", backend, "error", err)
			healthy = false
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Start debounce timer if healthy and not currently announced
	if healthy && !m.isAnnounced.Load() {
		if m.debounceTimer != nil {
			m.debounceTimer.Stop()
		}
		if m.debounceDuration == 0 {
			// Zero debounce: act immediately
			m.announceLocked(ctx)
		} else {
			// Use channel-based debounce: timer fires signal to Start() loop
			// which then calls announceLocked (avoiding mutex re-entry in callback)
			m.debounceTimer = time.AfterFunc(m.debounceDuration, func() {
				select {
				case m.debounceCh <- struct{}{}:
				default:
				}
			})
		}
		return
	}

	// Withdraw immediately on unhealthy (no debounce for failure)
	if !healthy && m.isAnnounced.Load() {
		m.withdrawLocked(ctx)
	}
}

// announceLocked binds VIP and announces BGP. Caller must hold mu.
func (m *AnycastManager) announceLocked(ctx context.Context) {
	m.logger.Info("node healthy, initiating anycast announcement")

	// 1. Bind VIP if not already bound (check-and-set under lock)
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
	metrics.BGPAnnounced.Set(1)
}

// withdrawLocked withdraws BGP. Caller must hold mu.
func (m *AnycastManager) withdrawLocked(ctx context.Context) {
	m.logger.Warn("node unhealthy, withdrawing anycast announcement")

	if err := m.routing.Withdraw(ctx, m.vip); err != nil {
		m.logger.Error("failed to withdraw BGP", "error", err)
		return // Do not clear isAnnounced flag if withdrawal failed
	}

	m.isAnnounced.Store(false)
	metrics.BGPAnnounced.Set(0)
	// We keep the VIP bound to the interface for local connectivity/checks
}
