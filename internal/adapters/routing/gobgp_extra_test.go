package routing

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	pb "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
)

// mockBGPBackendWithCapture captures AddPeer requests to verify AuthPassword
type mockBGPBackendWithCapture struct {
	failAddPath    bool
	failDeletePath bool
	failAddPeer    bool
	lastAddPeerReq *pb.AddPeerRequest
}

func (m *mockBGPBackendWithCapture) Serve()                                                           {}
func (m *mockBGPBackendWithCapture) Stop()                                                          {}
func (m *mockBGPBackendWithCapture) StartBgp(_ context.Context, _ *pb.StartBgpRequest) error         { return nil }
func (m *mockBGPBackendWithCapture) AddPath(_ apiutil.AddPathRequest) ([]apiutil.AddPathResponse, error) {
	if m.failAddPath {
		return nil, errors.New("add path failed")
	}
	return []apiutil.AddPathResponse{{}}, nil
}
func (m *mockBGPBackendWithCapture) DeletePath(_ apiutil.DeletePathRequest) error {
	if m.failDeletePath {
		return errors.New("delete path failed")
	}
	return nil
}
func (m *mockBGPBackendWithCapture) AddPeer(_ context.Context, r *pb.AddPeerRequest) error {
	if m.failAddPeer {
		return errors.New("add peer failed")
	}
	m.lastAddPeerReq = r
	return nil
}

func TestGoBGPAdapter_SetConfig(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	adapter.SetConfig("1.2.3.4", 1790, "1.2.3.1", "")

	if adapter.routerID != "1.2.3.4" {
		t.Errorf("routerID not set correctly")
	}
	if adapter.listenPort != 1790 {
		t.Errorf("listenPort not set correctly")
	}
	if adapter.nextHop != "1.2.3.1" {
		t.Errorf("nextHop not set correctly")
	}

	// Test partial update
	adapter.SetConfig("", 0, "8.8.8.8", "")
	if adapter.routerID != "1.2.3.4" {
		t.Errorf("routerID should not have changed")
	}
	if adapter.nextHop != "8.8.8.8" {
		t.Errorf("nextHop not updated correctly")
	}
}

func TestGoBGPAdapter_SetConfig_PeerPassword(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	adapter.SetConfig("1.2.3.4", 1790, "1.2.3.1", "mysecretpassword")

	if adapter.peerPassword != "mysecretpassword" {
		t.Errorf("expected peerPassword to be set, got %q", adapter.peerPassword)
	}

	// Verify empty string does NOT overwrite existing password
	adapter.SetConfig("", 0, "", "")
	if adapter.peerPassword != "mysecretpassword" {
		t.Errorf("expected peerPassword to remain after empty string update, got %q", adapter.peerPassword)
	}
}

func TestGoBGPAdapter_Announce_AtomicTrackingOnFailure(t *testing.T) {
	mock := &mockBGPBackendWithCapture{failAddPath: true}
	adapter := &GoBGPAdapter{
		bgpServer:     mock,
		logger:        slog.Default(),
		announcedVIPs: make(map[string]bool),
	}

	ctx := context.Background()
	err := adapter.Announce(ctx, "1.1.1.1")
	if err == nil {
		t.Fatal("expected error from failed AddPath")
	}

	// VIP should NOT be tracked because AddPath failed (atomicity)
	adapter.announcedMu.Lock()
	if adapter.announcedVIPs["1.1.1.1"] {
		t.Error("VIP should not be tracked after AddPath failure")
	}
	adapter.announcedMu.Unlock()
}

func TestGoBGPAdapter_Withdraw_AtomicTrackingOnFailure(t *testing.T) {
	mock := &mockBGPBackendWithCapture{}
	adapter := &GoBGPAdapter{
		bgpServer:     mock,
		logger:        slog.Default(),
		announcedVIPs: make(map[string]bool),
	}

	ctx := context.Background()

	// First announce successfully
	if err := adapter.Announce(ctx, "1.1.1.1"); err != nil {
		t.Fatalf("Announce failed: %v", err)
	}

	// Verify it's tracked
	adapter.announcedMu.Lock()
	if !adapter.announcedVIPs["1.1.1.1"] {
		t.Fatal("VIP should be tracked after successful Announce")
	}
	adapter.announcedMu.Unlock()

	// Now fail the withdraw
	mock.failDeletePath = true
	err := adapter.Withdraw(ctx, "1.1.1.1")
	if err == nil {
		t.Fatal("expected error from failed DeletePath")
	}

	// VIP should still be tracked because DeletePath failed (atomicity)
	adapter.announcedMu.Lock()
	if !adapter.announcedVIPs["1.1.1.1"] {
		t.Error("VIP should still be tracked after DeletePath failure")
	}
	adapter.announcedMu.Unlock()
}

func TestGoBGPAdapter_PeerPasswordAppliedToAddPeer(t *testing.T) {
	mock := &mockBGPBackendWithCapture{}
	adapter := &GoBGPAdapter{
		bgpServer:     mock,
		logger:        slog.Default(),
		peerPassword:  "secret123",
		announcedVIPs: make(map[string]bool),
	}

	ctx := context.Background()
	err := adapter.addPeer(ctx, 65002, "192.168.1.1")
	if err != nil {
		t.Fatalf("addPeer failed: %v", err)
	}

	if mock.lastAddPeerReq == nil {
		t.Fatal("AddPeer was not called")
	}
	if mock.lastAddPeerReq.Peer.Conf.AuthPassword != "secret123" {
		t.Errorf("expected AuthPassword 'secret123', got %q", mock.lastAddPeerReq.Peer.Conf.AuthPassword)
	}
}

func TestGoBGPAdapter_Announce_Error(t *testing.T) {
	adapter := &GoBGPAdapter{bgpServer: nil, logger: slog.Default()}
	if err := adapter.Announce(context.Background(), "1.1.1.1"); err == nil {
		t.Error("expected error for nil bgpServer")
	}
	if err := adapter.Withdraw(context.Background(), "1.1.1.1"); err == nil {
		t.Error("expected error for nil bgpServer")
	}
}

func TestGoBGPAdapter_InvalidIP(t *testing.T) {
	mock := &mockBGPBackend{}
	adapter := &GoBGPAdapter{bgpServer: mock, logger: slog.Default()}
	if err := adapter.Announce(context.Background(), "invalid"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := adapter.Withdraw(context.Background(), "invalid"); err == nil {
		t.Error("expected error for invalid IP")
	}
}
