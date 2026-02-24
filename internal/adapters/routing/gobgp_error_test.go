package routing

import (
	"context"
	"log/slog"
	"testing"
)

func TestGoBGPAdapter_Start_Errors(t *testing.T) {
	mock := &mockBGPBackend{}
	adapter := &GoBGPAdapter{
		bgpServer: mock,
		logger:    slog.Default(),
	}
	ctx := context.Background()

	// 1. Fail StartBgp
	mock.failStartBgp = true
	if err := adapter.Start(ctx, 65001, 65002, "127.0.0.1"); err == nil {
		t.Error("expected error from failed StartBgp")
	}

	// 2. Fail AddPeer
	mock.failStartBgp = false
	mock.failAddPeer = true
	if err := adapter.Start(ctx, 65001, 65002, "127.0.0.1"); err == nil {
		t.Error("expected error from failed AddPeer")
	}
}
