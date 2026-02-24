package testutil

import (
	"context"
	"testing"
)

func TestMocks(t *testing.T) {
	ctx := context.Background()
	
	// Test MockRoutingEngine
	re := &MockRoutingEngine{}
	_ = re.Start(ctx, 1, 2, "1.1.1.1")
	_ = re.Announce(ctx, "1.1.1.1")
	if !re.Announced {
		t.Error("expected announced to be true")
	}
	_ = re.Withdraw(ctx, "1.1.1.1")
	if re.Announced {
		t.Error("expected announced to be false")
	}
	if re.WithdrawCount != 1 {
		t.Errorf("expected withdraw count 1, got %d", re.WithdrawCount)
	}
	_ = re.Stop()
	
	re.FailAnnounce = true
	if err := re.Announce(ctx, "1.1.1.1"); err == nil {
		t.Error("expected error from failed announce")
	}

	// Test MockVIPManager
	vm := &MockVIPManager{}
	_ = vm.Bind(ctx, "1.1.1.1", "lo")
	if !vm.Bound {
		t.Error("expected bound to be true")
	}
	_ = vm.Unbind(ctx, "1.1.1.1", "lo")
	if vm.Bound {
		t.Error("expected bound to be false")
	}
	
	vm.FailBind = true
	if err := vm.Bind(ctx, "1.1.1.1", "lo"); err == nil {
		t.Error("expected error from failed bind")
	}
}
