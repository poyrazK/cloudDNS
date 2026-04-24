package testutil

import (
	"context"
	"errors"
)

// MockRoutingEngine implements ports.RoutingEngine for testing.
type MockRoutingEngine struct {
	Announced        bool
	WithdrawCount    int
	AnnounceAttempts int
	WithdrawAttempts int
	FailAnnounce     bool
	FailWithdraw     bool
}

// Start implements ports.RoutingEngine for testing.
func (m *MockRoutingEngine) Start(_ context.Context, _, _ uint32, _ string) error { return nil }
// Announce implements ports.RoutingEngine for testing.
func (m *MockRoutingEngine) Announce(_ context.Context, _ string) error {
	m.AnnounceAttempts++
	if m.FailAnnounce {
		return errors.New("announce failed")
	}
	m.Announced = true
	return nil
}
// Withdraw implements ports.RoutingEngine for testing.
func (m *MockRoutingEngine) Withdraw(_ context.Context, _ string) error {
	m.WithdrawAttempts++
	if m.FailWithdraw {
		return errors.New("withdraw failed")
	}
	m.Announced = false
	m.WithdrawCount++
	return nil
}
// Stop implements ports.RoutingEngine for testing.
func (m *MockRoutingEngine) Stop() error { return nil }

// MockVIPManager implements ports.VIPManager for testing.
type MockVIPManager struct {
	Bound    bool
	FailBind bool
}

// Bind implements ports.VIPManager for testing.
func (m *MockVIPManager) Bind(_ context.Context, _, _ string) error {
	if m.FailBind {
		return errors.New("bind failed")
	}
	m.Bound = true
	return nil
}
// Unbind implements ports.VIPManager for testing.
func (m *MockVIPManager) Unbind(_ context.Context, _, _ string) error {
	m.Bound = false
	return nil
}
