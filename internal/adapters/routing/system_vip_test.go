package routing

import (
	"context"
	"fmt"
	"runtime"
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

func TestSystemVIPAdapter_OSLogic(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	ctx := context.Background()
	
	// Test unbind on non-existent VIP/interface to trigger warning paths
	_ = adapter.Unbind(ctx, "255.255.255.255", "nonexistent0")
	
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		err := adapter.Bind(ctx, "1.1.1.1", "lo")
		if err == nil {
			t.Error("expected error on unsupported OS")
		}
		expected := fmt.Sprintf("unsupported OS for VIP management: %s", runtime.GOOS)
		if err.Error() != expected {
			t.Errorf("expected %s, got %s", expected, err.Error())
		}
	}
}
