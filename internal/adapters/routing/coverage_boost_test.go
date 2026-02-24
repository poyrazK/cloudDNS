package routing

import (
	"log/slog"
	"testing"
)

func TestGoBGPAdapter_Stop_Nil(t *testing.T) {
	adapter := &GoBGPAdapter{bgpServer: nil, logger: slog.Default()}
	if err := adapter.Stop(); err != nil {
		t.Errorf("expected no error from Stop even if server is nil")
	}
}

func TestSystemVIPAdapter_UnsupportedOS_Direct(t *testing.T) {
	adapter := NewSystemVIPAdapter(nil)
	err := adapter.handleUnsupportedOS()
	if err == nil {
		t.Error("expected error from handleUnsupportedOS")
	}
}
