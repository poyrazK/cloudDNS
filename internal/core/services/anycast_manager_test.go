package services

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

type mockAnycastDNSService struct {
	healthy bool
}

func (m *mockAnycastDNSService) HealthCheck(_ context.Context) map[string]error {
	res := make(map[string]error)
	if !m.healthy {
		res["mock"] = errors.New("unhealthy")
	} else {
		res["mock"] = nil
	}
	return res
}

func (m *mockAnycastDNSService) CreateZone(_ context.Context, _ *domain.Zone) error { return nil }
func (m *mockAnycastDNSService) CreateRecord(_ context.Context, _ *domain.Record) error { return nil }
func (m *mockAnycastDNSService) Resolve(_ context.Context, _ string, _ domain.RecordType, _ string) ([]domain.Record, error) { return nil, nil }
func (m *mockAnycastDNSService) ListZones(_ context.Context, _ string) ([]domain.Zone, error) { return nil, nil }
func (m *mockAnycastDNSService) ListRecordsForZone(_ context.Context, _ string) ([]domain.Record, error) { return nil, nil }
func (m *mockAnycastDNSService) DeleteZone(_ context.Context, _, _ string) error { return nil }
func (m *mockAnycastDNSService) DeleteRecord(_ context.Context, _, _ string) error { return nil }
func (m *mockAnycastDNSService) ImportZone(_ context.Context, _ string, _ io.Reader) (*domain.Zone, error) { return nil, nil }
func (m *mockAnycastDNSService) ListAuditLogs(_ context.Context, _ string) ([]domain.AuditLog, error) { return nil, nil }

type mockRoutingEngine struct {
	announced    bool
	failAnnounce bool
}

func (m *mockRoutingEngine) Start(_ context.Context, _, _ uint32, _ string) error { return nil }
func (m *mockRoutingEngine) Announce(_ context.Context, _ string) error {
	if m.failAnnounce {
		return errors.New("announce failed")
	}
	m.announced = true
	return nil
}
func (m *mockRoutingEngine) Withdraw(_ context.Context, _ string) error {
	m.announced = false
	return nil
}
func (m *mockRoutingEngine) Stop() error { return nil }

type mockVIPManager struct {
	bound    bool
	failBind bool
}

func (m *mockVIPManager) Bind(_ context.Context, _, _ string) error {
	if m.failBind {
		return errors.New("bind failed")
	}
	m.bound = true
	return nil
}
func (m *mockVIPManager) Unbind(_ context.Context, _, _ string) error {
	m.bound = false
	return nil
}

func TestAnycastManager_Lifecycle(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &mockRoutingEngine{}
	vipMgr := &mockVIPManager{}
	vip := "1.1.1.1"
	iface := "lo"

	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, vip, iface, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial check (healthy)
	mgr.TriggerCheck(ctx)
	if !routing.announced {
		t.Errorf("Expected BGP announcement when healthy")
	}
	if !vipMgr.bound {
		t.Errorf("Expected VIP to be bound when healthy")
	}

	// Become unhealthy
	dnsSvc.healthy = false
	mgr.TriggerCheck(ctx)
	if routing.announced {
		t.Errorf("Expected BGP withdrawal when unhealthy")
	}
	if !vipMgr.bound {
		t.Errorf("Expected VIP to stay bound even if unhealthy")
	}

	// Become healthy again
	dnsSvc.healthy = true
	mgr.TriggerCheck(ctx)
	if !routing.announced {
		t.Errorf("Expected BGP re-announcement when healthy again")
	}
}

func TestAnycastManager_Errors(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &mockRoutingEngine{}
	vipMgr := &mockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil)
	ctx := context.Background()

	// 1. Fail Bind
	vipMgr.failBind = true
	mgr.announce(ctx)
	if mgr.isAnnounced {
		t.Errorf("isAnnounced should be false if bind fails")
	}

	// 2. Fail Announce
	vipMgr.failBind = false
	routing.failAnnounce = true
	mgr.announce(ctx)
	if mgr.isAnnounced {
		t.Errorf("isAnnounced should be false if routing announce fails")
	}

	// 3. Withdraw when already withdrawn
	mgr.withdraw(ctx)
}

func TestAnycastManager_MultiBackend(t *testing.T) {
	// Mock a service with multiple backends
	dnsSvc := &mockMultiBackendService{
		status: map[string]error{
			"db":    nil,
			"redis": errors.New("timeout"),
		},
	}
	routing := &mockRoutingEngine{}
	vipMgr := &mockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil)
	
	mgr.TriggerCheck(context.Background())
	if routing.announced {
		t.Errorf("Should not announce if one backend is failing")
	}
}

type mockMultiBackendService struct {
	mockAnycastDNSService
	status map[string]error
}

func (m *mockMultiBackendService) HealthCheck(_ context.Context) map[string]error {
	return m.status
}

func TestAnycastManager_StartStop(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &mockRoutingEngine{}
	vipMgr := &mockVIPManager{}
	
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This just verifies it doesn't crash and respects context
	mgr.Start(ctx)
}

func TestAnycastManager_CoverageBoost(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &mockRoutingEngine{}
	vipMgr := &mockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil)
	ctx := context.Background()

	// 1. Withdraw when NOT announced
	mgr.withdraw(ctx) 
	if mgr.isAnnounced {
		t.Errorf("Should not be announced")
	}

	// 2. Announce when already healthy and announced
	mgr.isAnnounced = true
	mgr.TriggerCheck(ctx) // Should do nothing
	if !mgr.isAnnounced {
		t.Errorf("Should stay announced")
	}

	// 3. Trigger check with no backends (edge case)
	dnsSvc2 := &mockMultiBackendService{status: map[string]error{}}
	mgr2 := NewAnycastManager(dnsSvc2, routing, vipMgr, "1.1.1.1", "lo", nil)
	mgr2.TriggerCheck(ctx)
	if !mgr2.isAnnounced {
		t.Errorf("Empty health map should be considered healthy")
	}
}
