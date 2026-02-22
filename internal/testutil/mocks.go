package testutil

import (
	"context"
	"errors"
)

// MockRoutingEngine implements ports.RoutingEngine for testing.
type MockRoutingEngine struct {
	Announced     bool
	WithdrawCount int
	FailAnnounce  bool
}

func (m *MockRoutingEngine) Start(_ context.Context, _, _ uint32, _ string) error { return nil }
func (m *MockRoutingEngine) Announce(_ context.Context, _ string) error {
	if m.FailAnnounce {
		return errors.New("announce failed")
	}
	m.Announced = true
	return nil
}
func (m *MockRoutingEngine) Withdraw(_ context.Context, _ string) error {
	m.Announced = false
	m.WithdrawCount++
	return nil
}
func (m *MockRoutingEngine) Stop() error { return nil }

// MockVIPManager implements ports.VIPManager for testing.
type MockVIPManager struct {
	Bound    bool
	FailBind bool
}

func (m *MockVIPManager) Bind(_ context.Context, _, _ string) error {
	if m.FailBind {
		return errors.New("bind failed")
	}
	m.Bound = true
	return nil
}
func (m *MockVIPManager) Unbind(_ context.Context, _, _ string) error {
	m.Bound = false
	return nil
}
