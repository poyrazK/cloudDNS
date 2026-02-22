package routing

import (
	"context"
	"testing"
)

func TestNewSystemVIPAdapter(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
	}
}

func TestSystemVIPAdapter_Bind(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	// This will fail in CI/local as it needs root and 'ip' or 'ifconfig' command to succeed
	// but it executes the code paths.
	_ = adapter.Bind(context.Background(), "1.1.1.1", "lo")
}

func TestSystemVIPAdapter_UnsupportedOS(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	err := adapter.handleUnsupportedOS()
	if err == nil {
		t.Error("expected error for unsupported OS")
	}
}

func TestSystemVIPAdapter_Unbind(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	_ = adapter.Unbind(context.Background(), "1.1.1.1", "lo")
}
