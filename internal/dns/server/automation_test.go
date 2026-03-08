package server

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestServer_AutomateDNSSEC(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "auto.test.", TenantID: "t1"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Manually trigger automation
	srv.automateDNSSEC()

	// Verify keys were generated for the zone
	keys, _ := repo.ListKeysForZone(context.Background(), "z1")
	if len(keys) < 2 {
		t.Errorf("Expected at least 2 keys (KSK+ZSK), got %d", len(keys))
	}
}

func TestServer_AutomateDNSSEC_ListError(t *testing.T) {
	repo := &mockServerRepo{
		failListZones: true,
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	// Should not panic, just return
	srv.automateDNSSEC()
}

func TestServer_AutomateDNSSEC_AutomateError(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "fail.test.", TenantID: "t1"},
		},
		failCreateKey: true,
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	// Should log error and continue
	srv.automateDNSSEC()
}
