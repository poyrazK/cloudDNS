package routing

import (
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
