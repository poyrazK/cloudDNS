package routing

import (
	"context"
	"log/slog"
	"testing"
	"time"
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

func TestGoBGPAdapter_Announce_Timeout(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	// Use a short timeout to prevent deadlocks if the background BGP loop isn't running.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := adapter.Announce(ctx, "1.1.1.1")
	if err == nil {
		t.Error("expected error (timeout) when announcing on non-started server")
	}
}

func TestGoBGPAdapter_Withdraw_Timeout(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := adapter.Withdraw(ctx, "1.1.1.1")
	if err == nil {
		t.Error("expected error (timeout) when withdrawing on non-started server")
	}
}
