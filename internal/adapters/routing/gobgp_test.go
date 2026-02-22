package routing

import (
	"testing"
)

func TestNewGoBGPAdapter(t *testing.T) {
	adapter := NewGoBGPAdapter(nil)
	if adapter == nil {
		t.Fatal("expected adapter to be non-nil")
	}
}
