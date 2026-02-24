package routing

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

type mockExecutor struct {
	output []byte
	err    error
}

func (m *mockExecutor) Run(ctx context.Context, name string, arg ...string) ([]byte, error) {
	return m.output, m.err
}

func TestSystemVIPAdapter_Mocked(t *testing.T) {
	ctx := context.Background()
	mock := &mockExecutor{}
	
	adapter := &SystemVIPAdapter{
		logger:   slog.Default(),
		executor: mock,
		os:       "linux",
	}

	// 1. Linux Success
	if err := adapter.Bind(ctx, "1.1.1.1", "lo"); err != nil {
		t.Errorf("Linux Bind failed: %v", err)
	}
	if err := adapter.Unbind(ctx, "1.1.1.1", "lo"); err != nil {
		t.Errorf("Linux Unbind failed: %v", err)
	}

	// 2. Darwin Success
	adapter.os = "darwin"
	if err := adapter.Bind(ctx, "1.1.1.1", "lo0"); err != nil {
		t.Errorf("Darwin Bind failed: %v", err)
	}
	if err := adapter.Unbind(ctx, "1.1.1.1", "lo0"); err != nil {
		t.Errorf("Darwin Unbind failed: %v", err)
	}

	// 3. Already Bound (Idempotency)
	adapter.os = "linux"
	mock.err = errors.New("exit status 2")
	mock.output = []byte("File exists")
	if err := adapter.Bind(ctx, "1.1.1.1", "lo"); err != nil {
		t.Errorf("expected idempotent bind success, got %v", err)
	}

	// 4. Real Error
	mock.output = []byte("Permission denied")
	if err := adapter.Bind(ctx, "1.1.1.1", "lo"); err == nil {
		t.Error("expected error from failed command")
	}
	if err := adapter.Unbind(ctx, "1.1.1.1", "lo"); err == nil {
		t.Error("expected error from failed command in Unbind")
	}

	// 5. Unsupported OS
	adapter.os = "windows"
	if err := adapter.Bind(ctx, "1.1.1.1", "lo"); err == nil {
		t.Error("expected error for unsupported OS")
	}
	if err := adapter.Unbind(ctx, "1.1.1.1", "lo"); err == nil {
		t.Error("expected error for unsupported OS in Unbind")
	}
}
