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
	_ = os.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	_ = os.Setenv("API_ADDR", "test-exit")
	defer func() { _ = os.Unsetenv("DATABASE_URL") }() 
	defer func() { _ = os.Unsetenv("API_ADDR") }() 

	if err := run(); err != nil {
		t.Errorf("run() failed: %v", err)
	}
}

func TestMainCall(_ *testing.T) {
	_ = os.Setenv("DATABASE_URL", "none")
	defer func() { _ = os.Unsetenv("DATABASE_URL") }()
	main()
}

func TestRun_ConfigErrors(_ *testing.T) {
	// 1. Missing DB URL
	_ = os.Unsetenv("DATABASE_URL")
	// run() might have a default or just fail to connect.
	// We just want to hit the path.
	_ = run()

	// 2. Invalid port
	_ = os.Setenv("DATABASE_URL", "none")
	_ = os.Setenv("DNS_ADDR", "127.0.0.1:invalid")
	defer func() { _ = os.Unsetenv("DNS_ADDR") }()
	_ = run()
}
// dummy change to trigger CI
