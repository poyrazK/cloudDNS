package services

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/testutil"
)

// emptyRecordIterator is a safe iterator that always returns false.
type emptyRecordIterator struct{}

func (e *emptyRecordIterator) Next() bool   { return false }
func (e *emptyRecordIterator) Record() domain.Record { return domain.Record{} }
func (e *emptyRecordIterator) Err() error  { return nil }
func (e *emptyRecordIterator) Close() error { return nil }

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

func (m *mockAnycastDNSService) CreateZone(_ context.Context, _ *domain.Zone) error     { return nil }
func (m *mockAnycastDNSService) CreateRecord(_ context.Context, _ *domain.Record) error { return nil }
func (m *mockAnycastDNSService) Resolve(_ context.Context, _ string, _ domain.RecordType, _ string) ([]domain.Record, error) {
	return nil, nil
}
func (m *mockAnycastDNSService) ListZones(_ context.Context, _ string) ([]domain.Zone, error) {
	return nil, nil
}
func (m *mockAnycastDNSService) ListRecordsForZone(_ context.Context, _, _ string) ([]domain.Record, error) {
	return nil, nil
}
func (m *mockAnycastDNSService) DeleteZone(_ context.Context, _, _ string) error      { return nil }
func (m *mockAnycastDNSService) DeleteRecord(_ context.Context, _, _, _ string) error { return nil }
func (m *mockAnycastDNSService) ImportZone(_ context.Context, _ string, _ io.Reader) (*domain.Zone, error) {
	return nil, nil
}
func (m *mockAnycastDNSService) ListAuditLogs(_ context.Context, _ string) ([]domain.AuditLog, error) {
	return nil, nil
}

func (m *mockAnycastDNSService) GetRecordsToProbeStreaming(_ context.Context) (ports.RecordIterator, error) {
	return &emptyRecordIterator{}, nil
}

func (m *mockAnycastDNSService) UpdateRecordHealth(_ context.Context, _ string, _ domain.HealthStatus, _ string) error {
	return nil
}

func (m *mockAnycastDNSService) UpdateRecord(_ context.Context, record *domain.Record) error {
	return nil
}

func (m *mockAnycastDNSService) CreateCatalogZone(_ context.Context, _, _ string) (*domain.CatalogZone, error) { return nil, nil }
func (m *mockAnycastDNSService) GetCatalogZone(_ context.Context, _ string) (*domain.CatalogZone, error)      { return nil, nil }
func (m *mockAnycastDNSService) ListCatalogZones(_ context.Context, _ string) ([]domain.CatalogZone, error)  { return nil, nil }
func (m *mockAnycastDNSService) DeleteCatalogZone(_ context.Context, _, _ string) error                     { return nil }
func (m *mockAnycastDNSService) AddZoneToCatalog(_ context.Context, _, _, _, _ string) error                 { return nil }
func (m *mockAnycastDNSService) RemoveZoneFromCatalog(_ context.Context, _, _ string) error                 { return nil }
func (m *mockAnycastDNSService) ListZoneCatalogEntries(_ context.Context, _ string) ([]domain.ZoneCatalogEntry, error) {
	return nil, nil
}
func (m *mockAnycastDNSService) PollCatalogZone(_ context.Context, _, _ string) ([]domain.ZoneCatalogEntry, error) { return nil, nil }
func (m *mockAnycastDNSService) SyncZonesFromCatalog(_ context.Context, _, _ string) error { return nil }

func TestAnycastManager_Lifecycle(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &testutil.MockRoutingEngine{}
	vipMgr := &testutil.MockVIPManager{}
	vip := "1.1.1.1"
	iface := "lo"

	// Debounce set to 0 for immediate transition in tests
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, vip, iface, nil, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial check (healthy)
	mgr.TriggerCheck(ctx)
	if !routing.Announced {
		t.Errorf("Expected BGP announcement when healthy")
	}
	if !vipMgr.Bound {
		t.Errorf("Expected VIP to be bound when healthy")
	}

	// Become unhealthy
	dnsSvc.healthy = false
	mgr.TriggerCheck(ctx)
	if routing.Announced {
		t.Errorf("Expected BGP withdrawal when unhealthy")
	}
	if !vipMgr.Bound {
		t.Errorf("Expected VIP to stay bound even if unhealthy")
	}

	// Become healthy again
	dnsSvc.healthy = true
	mgr.TriggerCheck(ctx)
	if !routing.Announced {
		t.Errorf("Expected BGP re-announcement when healthy again")
	}
}

func TestAnycastManager_Errors(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &testutil.MockRoutingEngine{}
	vipMgr := &testutil.MockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil, 0)
	ctx := context.Background()

	// 1. Fail Bind
	vipMgr.FailBind = true
	mgr.announceLocked(ctx)
	if mgr.isAnnounced.Load() {
		t.Errorf("isAnnounced should be false if bind fails")
	}

	// 2. Fail Announce
	vipMgr.FailBind = false
	routing.FailAnnounce = true
	mgr.announceLocked(ctx)
	if mgr.isAnnounced.Load() {
		t.Errorf("isAnnounced should be false if routing announce fails")
	}

	// 3. Withdraw when already withdrawn
	mgr.withdrawLocked(ctx)
}

func TestAnycastManager_MultiBackend(t *testing.T) {
	// Mock a service with multiple backends
	dnsSvc := &mockMultiBackendService{
		status: map[string]error{
			"db":    nil,
			"redis": errors.New("timeout"),
		},
	}
	routing := &testutil.MockRoutingEngine{}
	vipMgr := &testutil.MockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil, 0)

	mgr.TriggerCheck(context.Background())
	if routing.Announced {
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

func (m *mockMultiBackendService) GetRecordsToProbeStreaming(_ context.Context) (ports.RecordIterator, error) {
	return &emptyRecordIterator{}, nil
}

func (m *mockMultiBackendService) UpdateRecordHealth(_ context.Context, _ string, _ domain.HealthStatus, _ string) error {
	return nil
}

func (m *mockMultiBackendService) UpdateRecord(_ context.Context, record *domain.Record) error {
	return nil
}

func TestAnycastManager_StartStop(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &testutil.MockRoutingEngine{}
	vipMgr := &testutil.MockVIPManager{}

	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This just verifies it doesn't crash and respects context
	mgr.Start(ctx)
}

func TestAnycastManager_CoverageBoost(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &testutil.MockRoutingEngine{}
	vipMgr := &testutil.MockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil, 0)
	ctx := context.Background()

	// 1. Withdraw when NOT announced
	mgr.withdrawLocked(ctx)
	if mgr.isAnnounced.Load() {
		t.Errorf("Should not be announced")
	}

	// 2. Announce when already healthy and announced
	mgr.isAnnounced.Store(true)
	mgr.TriggerCheck(ctx) // Should do nothing
	if !mgr.isAnnounced.Load() {
		t.Errorf("Should stay announced")
	}

	// 3. Trigger check with no backends (edge case)
	dnsSvc2 := &mockMultiBackendService{status: map[string]error{}}
	mgr2 := NewAnycastManager(dnsSvc2, routing, vipMgr, "1.1.1.1", "lo", nil, 0)
	mgr2.TriggerCheck(ctx)
	if !mgr2.isAnnounced.Load() {
		t.Errorf("Empty health map should be considered healthy")
	}

	// 4. Withdraw error path
	routing.FailWithdraw = true
	mgr.isAnnounced.Store(true)
	mgr.withdrawLocked(ctx)
	if !mgr.isAnnounced.Load() {
		t.Errorf("Should remain announced if withdrawal fails")
	}
}

func TestAnycastManager_StartWithdrawError(t *testing.T) {
	dnsSvc := &mockAnycastDNSService{healthy: true}
	routing := &testutil.MockRoutingEngine{FailWithdraw: true}
	vipMgr := &testutil.MockVIPManager{}
	mgr := NewAnycastManager(dnsSvc, routing, vipMgr, "1.1.1.1", "lo", nil, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Trigger shutdown immediately
	mgr.Start(ctx)

	// Verify that withdraw was attempted despite FailWithdraw being true
	if routing.WithdrawAttempts == 0 {
		t.Errorf("Expected withdraw attempt during shutdown")
	}
}
