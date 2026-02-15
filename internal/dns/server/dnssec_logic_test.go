package server

import (
	"context"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestGenerateNSEC(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: domain.TypeSOA},
			{ZoneID: "z1", Name: "a.example.com.", Type: domain.TypeA},
			{ZoneID: "z1", Name: "z.example.com.", Type: domain.TypeA},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	// 1. Query for something in between 'a' and 'z'
	nsec, err := srv.generateNSEC(context.Background(), zone, "m.example.com.")
	if errScan != nil {
		t.Fatalf("generateNSEC failed: %v", err)
	}
	// example.com. < a.example.com. < m.example.com. < z.example.com.
	if nsec.Name != "a.example.com." || nsec.NextName != "z.example.com." {
		t.Errorf("Wrong NSEC range: %s -> %s", nsec.Name, nsec.NextName)
	}

	// 2. Query for something before 'a' but after root
	nsec, _ = srv.generateNSEC(context.Background(), zone, "0.example.com.")
	if nsec.Name != "example.com." || nsec.NextName != "a.example.com." {
		t.Errorf("Wrong NSEC start range: %s -> %s", nsec.Name, nsec.NextName)
	}

	// 3. Wrap around: Query for something after 'z'
	nsec, _ = srv.generateNSEC(context.Background(), zone, "{.example.com.")
	if nsec.Name != "z.example.com." || nsec.NextName != "example.com." {
		t.Errorf("Wrong NSEC wrap-around: %s -> %s", nsec.Name, nsec.NextName)
	}
}

func TestGenerateNSEC3(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{{ID: "z1", Name: "example.com."}},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: domain.TypeSOA},
			{ZoneID: "z1", Name: "example.com.", Type: "NSEC3PARAM", Content: "1 0 10 ABCD"},
			{ZoneID: "z1", Name: "www.example.com.", Type: domain.TypeA},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	nsec3, err := srv.generateNSEC3(context.Background(), zone, "missing.example.com.")
	if errScan != nil {
		t.Fatalf("generateNSEC3 failed: %v", err)
	}

	if nsec3.Type != packet.NSEC3 {
		t.Errorf("Expected NSEC3 record type")
	}
	if nsec3.Iterations != 10 || string(nsec3.Salt) != "ABCD" {
		t.Errorf("NSEC3 metadata mismatch")
	}
}

func TestGenerateNSEC3_NoParam(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	_, err := srv.generateNSEC3(context.Background(), zone, "test")
	if err == nil {
		t.Errorf("Expected error when NSEC3PARAM is missing")
	}
}
