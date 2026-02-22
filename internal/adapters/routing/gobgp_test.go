package routing

import (
	"context"
	"testing"
)

func TestNewGoBGPAdapter(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
	}
}

func TestGoBGPAdapter_Announce_Error(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	// Should fail because server is not started
	err := adapter.Announce(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error when announcing on non-started server")
	}
}

func TestGoBGPAdapter_Withdraw_Error(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	// Should fail because server is not started
	err := adapter.Withdraw(context.Background(), "1.1.1.1")
	if err == nil {
		t.Error("expected error when withdrawing on non-started server")
	}
}
