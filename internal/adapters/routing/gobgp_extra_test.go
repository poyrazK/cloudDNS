package routing

import (
	"context"
	"log/slog"
	"testing"
)

func TestGoBGPAdapter_SetConfig(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	adapter.SetConfig("1.2.3.4", 1790, "1.2.3.1")
	
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
	adapter.SetConfig("", 0, "8.8.8.8")
	if adapter.routerID != "1.2.3.4" {
		t.Errorf("routerID should not have changed")
	}
	if adapter.nextHop != "8.8.8.8" {
		t.Errorf("nextHop not updated correctly")
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
