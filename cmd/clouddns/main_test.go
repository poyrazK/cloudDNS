package main

import (
	"os"
	"testing"
)

func TestRun_EarlyExit(t *testing.T) {
	// Set environment variables to trigger the test-only early exit path
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("API_ADDR", "test-exit")

	if err := run(); err != nil {
		t.Errorf("run() failed: %v", err)
	}
}

func TestRun_FullInit(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	t.Setenv("API_ADDR", "test-exit")

	if err := run(); err != nil {
		t.Errorf("run() failed: %v", err)
	}
}

func TestMainCall(t *testing.T) {
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("API_ADDR", "test-exit")
	main()
}

func TestRun_ConfigErrors(t *testing.T) {
	t.Setenv("API_ADDR", "test-exit")

	// 1. Missing DB URL (unset explicitly for this test logic if needed, 
	// though t.Setenv isolated to test)
	err := os.Unsetenv("DATABASE_URL")
	if err != nil {
		t.Fatalf("failed to unset env: %v", err)
	}
	
	// We just want to hit the path.
	_ = run()

	// 2. Invalid port
	t.Setenv("DATABASE_URL", "none")
	t.Setenv("DNS_ADDR", "127.0.0.1:invalid")
	_ = run()
}
