package main

import (
	"os"
	"testing"
)

func TestRun_EarlyExit(t *testing.T) {
	// Set environment variables to trigger the test-only early exit path
	os.Setenv("DATABASE_URL", "none")
	defer os.Unsetenv("DATABASE_URL")

	if err := run(); err != nil {
		t.Errorf("run() failed: %v", err)
	}
}
