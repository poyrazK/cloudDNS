package main

import (
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

func TestRun_ConfigErrors(t *testing.T) {
	// Test DBURL="none" exit
	os.Setenv("DATABASE_URL", "none")
	defer os.Unsetenv("DATABASE_URL")
	if err := run(); err != nil {
		t.Errorf("Expected nil for DBURL=none, got %v", err)
	}

	// Test test-exit
	os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
	os.Setenv("API_ADDR", "test-exit")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("API_ADDR")

	_ = run()
}

func TestRun_AnycastMissingConfig(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://localhost:5432/test")
	os.Setenv("ANYCAST_ENABLED", "true")
	os.Setenv("ANYCAST_VIP", "") // Missing
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("ANYCAST_ENABLED")
	defer os.Unsetenv("ANYCAST_VIP")

	err := run()
	if err == nil || err.Error() == "" {
		t.Error("expected error for missing ANYCAST_VIP")
	}
}

func TestRun_AnycastCompleteConfig(t *testing.T) {
	os.Setenv("DATABASE_URL", "none")
	os.Setenv("ANYCAST_ENABLED", "true")
	os.Setenv("ANYCAST_VIP", "1.1.1.1")
	os.Setenv("BGP_PEER_IP", "1.1.1.2")
	os.Setenv("BGP_ROUTER_ID", "1.1.1.1")
	os.Setenv("BGP_NEXT_HOP", "1.1.1.1")
	os.Setenv("API_ADDR", "test-exit")

	defer os.Unsetenv("ANYCAST_ENABLED")
	defer os.Unsetenv("ANYCAST_VIP")
	defer os.Unsetenv("BGP_PEER_IP")
	defer os.Unsetenv("BGP_ROUTER_ID")
	defer os.Unsetenv("BGP_NEXT_HOP")
	defer os.Unsetenv("API_ADDR")

	_ = run()
}

func TestRun_RedisConnectionFailure(t *testing.T) {
	os.Setenv("DATABASE_URL", "none")
	os.Setenv("REDIS_URL", "invalid.local:6379")
	defer os.Unsetenv("REDIS_URL")

	err := run()
	if err == nil {
		t.Error("expected error for invalid redis url")
	}
}

func TestRun_FullLifecycle(t *testing.T) {
	os.Setenv("DATABASE_URL", "none")
	os.Setenv("API_ADDR", ":0") // Use random port for testing
	os.Setenv("DNS_ADDR", "127.0.0.1:0")

	// Start the application in a background goroutine
	done := make(chan error, 1)
	go func() {
		done <- run()
	}()

	// Wait briefly for the server to spin up
	// Rather than a race condition, send an interrupt to gracefully shut it down
	p, err := os.FindProcess(os.Getpid())
	if err == nil {
		p.Signal(os.Interrupt)
	}

	err = <-done
	if err != nil {
		t.Errorf("Application failed during full lifecycle run: %v", err)
	}
}
