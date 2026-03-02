package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/testutil"
	"github.com/stretchr/testify/mock"
)

func TestHealthMonitor_ProbeHTTP(t *testing.T) {
	// 1. Success Case
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	m := NewHealthMonitor(nil, nil)
	status, msg := m.probeHTTP(ts.URL)
	if status != domain.HealthStatusHealthy {
		t.Errorf("Expected Healthy, got %s (msg: %s)", status, msg)
	}

	// 2. Failure Case (404)
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tsErr.Close()

	status, _ = m.probeHTTP(tsErr.URL)
	if status != domain.HealthStatusUnhealthy {
		t.Errorf("Expected Unhealthy for 404, got %s", status)
	}

	// 3. Network Error
	status, _ = m.probeHTTP("http://localhost:1") // Closed port
	if status != domain.HealthStatusUnhealthy {
		t.Errorf("Expected Unhealthy for connection error, got %s", status)
	}
}

func TestHealthMonitor_ProbeTCP(t *testing.T) {
	// Success Case using a dummy HTTP server as a TCP endpoint
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	m := NewHealthMonitor(nil, nil)
	target := ts.Listener.Addr().String()
	status, _ := m.probeTCP(target)
	if status != domain.HealthStatusHealthy {
		t.Errorf("Expected Healthy for open TCP port, got %s", status)
	}

	// Failure Case
	status, _ = m.probeTCP("localhost:1")
	if status != domain.HealthStatusUnhealthy {
		t.Errorf("Expected Unhealthy for closed TCP port, got %s", status)
	}
}

func TestHealthMonitor_RunChecks(t *testing.T) {
	repo := &testutil.MockRepo{}
	m := NewHealthMonitor(repo, nil)

	// Mock server for probe target
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	records := []domain.Record{
		{
			ID:                "r1",
			HealthCheckType:   domain.HealthCheckHTTP,
			HealthCheckTarget: ts.URL,
		},
	}

	done := make(chan bool, 1)

	repo.On("GetRecordsToProbe", mock.Anything).Return(records, nil).Once()
	repo.On("UpdateRecordHealth", mock.Anything, "r1", domain.HealthStatusHealthy, "").
		Return(nil).
		Once().
		Run(func(args mock.Arguments) {
			done <- true
		})

	// Run checks and wait deterministically for the update to happen
	m.runChecks(context.Background())

	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for UpdateRecordHealth to be called")
	}

	repo.AssertExpectations(t)
}
