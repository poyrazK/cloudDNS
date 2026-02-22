package routing

import (
	"context"
	"log/slog"
	"testing"
)

func TestNewGoBGPAdapter(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
	}

	adapterWithLogger := NewGoBGPAdapter(slog.Default())
	if adapterWithLogger == nil {
		t.Fatal("expected adapter with logger to be non-nil")
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
