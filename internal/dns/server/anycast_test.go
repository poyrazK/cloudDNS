package server

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/services"
)

type mockAnycastRouting struct {
	announced     bool
	withdrawCount int
}

func (m *mockAnycastRouting) Start(_ context.Context, _, _ uint32, _ string) error { return nil }
func (m *mockAnycastRouting) Announce(_ context.Context, _ string) error {
	m.announced = true
	return nil
}
func (m *mockAnycastRouting) Withdraw(_ context.Context, _ string) error {
	m.announced = false
	m.withdrawCount++
	return nil
}
func (m *mockAnycastRouting) Stop() error { return nil }

type mockAnycastVIP struct {
	bound bool
}

func (m *mockAnycastVIP) Bind(_ context.Context, _, _ string) error { m.bound = true; return nil }
func (m *mockAnycastVIP) Unbind(_ context.Context, _, _ string) error { m.bound = false; return nil }

func TestSystem_AnycastHealthToBGP(t *testing.T) {
	// 1. Setup Service with Mock Repo
	repo := &mockServerRepo{}
	dnsSvc := services.NewDNSService(repo, nil)
	
	// 2. Setup Anycast Manager
	routing := &mockAnycastRouting{}
	vipMgr := &mockAnycastVIP{}
	vip := "1.1.1.1"
	iface := "lo"
	
	mgr := services.NewAnycastManager(dnsSvc, routing, vipMgr, vip, iface, nil)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// 3. Initial state: Healthy (mockServerRepo.Ping returns nil by default)
	mgr.TriggerCheck(ctx)
	
	// Check if announced
	if !routing.announced {
		t.Errorf("System should have announced VIP when healthy")
	}
	
	// 4. Simulate Failure
	repo.mu.Lock()
	repo.pingErr = context.DeadlineExceeded // Force HealthCheck to fail
	repo.mu.Unlock()
	
	// Trigger manual check instead of waiting for 10s ticker
	mgr.TriggerCheck(ctx)
	
	if routing.announced {
		t.Errorf("System should have withdrawn VIP when unhealthy")
	}
	if routing.withdrawCount != 1 {
		t.Errorf("Expected 1 withdrawal, got %d", routing.withdrawCount)
	}
}
