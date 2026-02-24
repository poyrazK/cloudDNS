package server

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/testutil"
)

func TestSystem_AnycastHealthToBGP(t *testing.T) {
	// 1. Setup Service with Mock Repo
	repo := &mockServerRepo{}
	dnsSvc := services.NewDNSService(repo, nil)
	
	// 2. Setup Anycast Manager
	routing := &testutil.MockRoutingEngine{}
	vipMgr := &testutil.MockVIPManager{}
	vip := "1.1.1.1"
	iface := "lo"
	
	mgr := services.NewAnycastManager(dnsSvc, routing, vipMgr, vip, iface, nil)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// 3. Initial state: Healthy (mockServerRepo.Ping returns nil by default)
	mgr.TriggerCheck(ctx)
	
	// Check if announced
	if !routing.Announced {
		t.Errorf("System should have announced VIP when healthy")
	}
	
	// 4. Simulate Failure
	repo.mu.Lock()
	repo.pingErr = context.DeadlineExceeded // Force HealthCheck to fail
	repo.mu.Unlock()
	
	// Trigger manual check instead of waiting for 10s ticker
	mgr.TriggerCheck(ctx)
	
	if routing.Announced {
		t.Errorf("System should have withdrawn VIP when unhealthy")
	}
	if routing.WithdrawCount != 1 {
		t.Errorf("Expected 1 withdrawal, got %d", routing.WithdrawCount)
	}
}
