package routing

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	pb "github.com/osrg/gobgp/v3/api"
)

type mockBGPBackend struct {
	failAddPath    bool
	failDeletePath bool
	failAddPeer    bool
}

func (m *mockBGPBackend) Serve() {}
func (m *mockBGPBackend) Stop()  {}
func (m *mockBGPBackend) AddPeer(ctx context.Context, r *pb.AddPeerRequest) error {
	if m.failAddPeer {
		return errors.New("add peer failed")
	}
	return nil
}
func (m *mockBGPBackend) AddPath(ctx context.Context, r *pb.AddPathRequest) (*pb.AddPathResponse, error) {
	if m.failAddPath {
		return nil, errors.New("add path failed")
	}
	return &pb.AddPathResponse{}, nil
}
func (m *mockBGPBackend) DeletePath(ctx context.Context, r *pb.DeletePathRequest) error {
	if m.failDeletePath {
		return errors.New("delete path failed")
	}
	return nil
}

func TestGoBGPAdapter_Mocked(t *testing.T) {
	mock := &mockBGPBackend{}
	adapter := &GoBGPAdapter{
		bgpServer: mock,
		logger:    slog.Default(),
	}

	ctx := context.Background()

	// 1. Successful Announce
	if err := adapter.Announce(ctx, "1.1.1.1"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// 2. Failed Announce
	mock.failAddPath = true
	if err := adapter.Announce(ctx, "1.1.1.1"); err == nil {
		t.Error("expected error from failed AddPath")
	}

	// 3. Successful Withdraw
	mock.failAddPath = false
	if err := adapter.Withdraw(ctx, "1.1.1.1"); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// 4. Failed Withdraw
	mock.failDeletePath = true
	if err := adapter.Withdraw(ctx, "1.1.1.1"); err == nil {
		t.Error("expected error from failed DeletePath")
	}

	// 5. Successful Start
	if err := adapter.Start(ctx, 65001, 65002, "127.0.0.1"); err != nil {
		t.Errorf("expected no error from Start, got %v", err)
	}

	// 6. Failed Start
	mock.failAddPeer = true
	if err := adapter.Start(ctx, 65001, 65002, "127.0.0.1"); err == nil {
		t.Error("expected error from failed AddPeer")
	}

	// 7. Stop
	_ = adapter.Stop()
}

func TestNewGoBGPAdapter(t *testing.T) {
	a := NewGoBGPAdapter(nil)
	if a == nil || a.bgpServer == nil {
		t.Fatal("NewGoBGPAdapter failed")
	}
}
