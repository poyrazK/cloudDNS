package main

import (
	"context"
	"testing"
)

func TestGetEnvUint32(t *testing.T) {
	t.Setenv("TEST_UINT32", "12345")

	if val := getEnvUint32("TEST_UINT32", 0); val != 12345 {
		t.Errorf("Expected 12345, got %d", val)
	}

	if val := getEnvUint32("NON_EXISTENT", 99); val != 99 {
		t.Errorf("Expected default 99, got %d", val)
	}

	t.Setenv("INVALID_UINT32", "not-a-number")
	if val := getEnvUint32("INVALID_UINT32", 42); val != 42 {
		t.Errorf("Expected default 42 for invalid input, got %d", val)
	}
}

func TestRunConfigErrors(t *testing.T) {
	ctx := context.Background()
	// Test DBURL="none" exit
	t.Setenv("DATABASE_URL", "none")
	if err := run(ctx); err != nil {
		t.Errorf("Expected nil for DBURL=none, got %v", err)
	}

	// Test test-exit
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
	t.Setenv("API_ADDR", "test-exit")

	_ = run(ctx)
}

func TestRunAnycastMissingConfig(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
	t.Setenv("ANYCAST_ENABLED", "true")
	t.Setenv("ANYCAST_VIP", "") // Missing

	err := run(ctx)
	if err == nil || err.Error() == "" {
		t.Error("expected error for missing ANYCAST_VIP")
	}
}

func TestRunAnycastCompleteConfig(t *testing.T) {
	const testVIP = "1.1.1.1"
	ctx := context.Background()
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("ANYCAST_ENABLED", "true")
	t.Setenv("ANYCAST_VIP", testVIP)
	t.Setenv("BGP_PEER_IP", "1.1.1.2")
	t.Setenv("BGP_ROUTER_ID", testVIP)
	t.Setenv("BGP_NEXT_HOP", testVIP)
	t.Setenv("API_ADDR", "test-exit")

	_ = run(ctx)
}

func TestRunRedisConnectionFailure(t *testing.T) {
	ctx := context.Background()
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("REDIS_URL", "invalid.local:6379")

	err := run(ctx)
	if err == nil {
		t.Error("expected error for invalid redis url")
	}
}

func TestRunAPIServerTLS(t *testing.T) {
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("API_ADDR", "test-exit") // Exit after initialization
	t.Setenv("API_TLS_CERT", "test.crt")
	t.Setenv("API_TLS_KEY", "test.key")

	// This should run and return nil because API_ADDR="test-exit"
	if err := run(context.Background()); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestRunFullLifecycle(t *testing.T) {
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("API_ADDR", ":0") // Use random port for testing
	t.Setenv("DNS_ADDR", "127.0.0.1:0")

	// Create a cancellable context to gracefully shutdown the app
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the application in a background goroutine
	done := make(chan error, 1)
	go func() {
		done <- run(ctx)
	}()

	// Since we use a cancellable context, we don't need to send SIGINT.
	// Cancel the context explicitly to initiate shutdown.
	cancel()

	err := <-done
	if err != nil {
		t.Errorf("Application failed during full lifecycle run: %v", err)
	}
}
