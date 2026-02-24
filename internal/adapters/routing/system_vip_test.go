package routing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func skipIfNotPrivileged(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping test: root privileges required for VIP management")
	}
	
	cmd := "ip"
	if runtime.GOOS == "darwin" {
		cmd = "ifconfig"
	}
	if _, err := exec.LookPath(cmd); err != nil {
		t.Skipf("Skipping test: %s command not found", cmd)
	}
}

func TestNewSystemVIPAdapter(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
	}
}

func TestSystemVIPAdapter_Bind(t *testing.T) {
	skipIfNotPrivileged(t)
	adapter := NewSystemVIPAdapter(nil)
	err := adapter.Bind(context.Background(), "127.0.0.2", "lo0")
	if err != nil {
		t.Errorf("Bind failed: %v", err)
	}
}

func TestSystemVIPAdapter_UnsupportedOS(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	err := adapter.handleUnsupportedOS()
	if err == nil {
		t.Error("expected error for unsupported OS")
	}
}

func TestSystemVIPAdapter_Unbind(t *testing.T) {
	skipIfNotPrivileged(t)
	adapter := NewSystemVIPAdapter(nil)
	_ = adapter.Unbind(context.Background(), "127.0.0.2", "lo0")
}

func TestSystemVIPAdapter_Validation(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	ctx := context.Background()

	if err := adapter.Bind(ctx, "invalid-ip", "lo"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := adapter.Bind(ctx, "1.1.1.1", ""); err == nil {
		t.Error("expected error for empty interface")
	}

	if err := adapter.Unbind(ctx, "invalid-ip", "lo"); err == nil {
		t.Error("expected error for invalid IP in Unbind")
	}
	if err := adapter.Unbind(ctx, "1.1.1.1", ""); err == nil {
		t.Error("expected error for empty interface in Unbind")
	}
}

func TestSystemVIPAdapter_OSLogic(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	ctx := context.Background()
	
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
