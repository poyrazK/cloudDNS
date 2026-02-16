package main

import (
	"os"
	"testing"
)

func TestRun_EarlyExit(t *testing.T) {
	// Set environment variables to trigger the test-only early exit path
	_ = os.Setenv("DATABASE_URL", "none")
	defer func() { _ = os.Unsetenv("DATABASE_URL") }() 

	if err := run(); err != nil {
		t.Errorf("run() failed: %v", err)
	}
}

func TestRun_FullInit(t *testing.T) {
	// Use a temporary file for sqlite-like path if needed, 
	// but here we just need a string that won't fail sql.Open
	_ = os.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	_ = os.Setenv("API_ADDR", "test-exit")
	defer func() { _ = os.Unsetenv("DATABASE_URL") }() 
	defer func() { _ = os.Unsetenv("API_ADDR") }() 

	if err := run(); err != nil {
		t.Errorf("run() failed: %v", err)
	}
}
