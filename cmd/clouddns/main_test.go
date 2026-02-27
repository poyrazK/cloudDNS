package main

import (
	"context"
	"os"
	"testing"
)

func TestGetEnvUint32(t *testing.T) {
	os.Setenv("TEST_UINT32", "12345")
	defer os.Unsetenv("TEST_UINT32")

	if val := getEnvUint32("TEST_UINT32", 0); val != 12345 {
		t.Errorf("Expected 12345, got %d", val)
	}

	if val := getEnvUint32("NON_EXISTENT", 99); val != 99 {
		t.Errorf("Expected default 99, got %d", val)
	}

	os.Setenv("INVALID_UINT32", "not-a-number")
	defer os.Unsetenv("INVALID_UINT32")
	if val := getEnvUint32("INVALID_UINT32", 42); val != 42 {
		t.Errorf("Expected default 42 for invalid input, got %d", val)
	}
}

func TestRunConfigErrors(t *testing.T) {
	ctx := context.Background()
	// Test DBURL="none" exit
	os.Setenv("DATABASE_URL", "none")
	defer os.Unsetenv("DATABASE_URL")
	if err := run(ctx); err != nil {
		t.Errorf("Expected nil for DBURL=none, got %v", err)
	}

	// Test test-exit
	os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
	os.Setenv("API_ADDR", "test-exit")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("API_ADDR")

	_ = run(ctx)
}

func TestRunAnycastMissingConfig(t *testing.T) {
	ctx := context.Background()
	os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
	os.Setenv("ANYCAST_ENABLED", "true")
	os.Setenv("ANYCAST_VIP", "") // Missing
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("ANYCAST_ENABLED")
	defer os.Unsetenv("ANYCAST_VIP")

	err := run(ctx)
	if err == nil || err.Error() == "" {
		t.Error("expected error for missing ANYCAST_VIP")
	}
}

func TestRunAnycastCompleteConfig(t *testing.T) {
	const testVIP = "1.1.1.1"
	ctx := context.Background()
	os.Setenv("DATABASE_URL", "none")
	os.Setenv("ANYCAST_ENABLED", "true")
	os.Setenv("ANYCAST_VIP", testVIP)
	os.Setenv("BGP_PEER_IP", "1.1.1.2")
	os.Setenv("BGP_ROUTER_ID", testVIP)
	os.Setenv("BGP_NEXT_HOP", testVIP)
	os.Setenv("API_ADDR", "test-exit")

	defer os.Unsetenv("ANYCAST_ENABLED")
	defer os.Unsetenv("ANYCAST_VIP")
	defer os.Unsetenv("BGP_PEER_IP")
	defer os.Unsetenv("BGP_ROUTER_ID")
	defer os.Unsetenv("BGP_NEXT_HOP")
	defer os.Unsetenv("API_ADDR")

	_ = run(ctx)
}

func TestRunRedisConnectionFailure(t *testing.T) {
	ctx := context.Background()
	os.Setenv("DATABASE_URL", "none")
	os.Setenv("REDIS_URL", "invalid.local:6379")
	defer os.Unsetenv("REDIS_URL")

	err := run(ctx)
	if err == nil {
		t.Error("expected error for invalid redis url")
	}
}

func TestRunFullLifecycle(t *testing.T) {
	os.Setenv("DATABASE_URL", "none")
	os.Setenv("API_ADDR", ":0") // Use random port for testing
	os.Setenv("DNS_ADDR", "127.0.0.1:0")

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
