package server

import (
	"context"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestGenerateNSEC(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
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
	if err != nil {
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
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: domain.TypeSOA},
			{ZoneID: "z1", Name: "example.com.", Type: "NSEC3PARAM", Content: "1 0 10 ABCD"},
			{ZoneID: "z1", Name: "www.example.com.", Type: domain.TypeA},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	nsec3, err := srv.generateNSEC3(context.Background(), zone, "missing.example.com.")
	if err != nil {
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

func TestGenerateNSEC_NoRecords(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	_, err := srv.generateNSEC(context.Background(), zone, "test")
	if err == nil {
		t.Errorf("Expected error when no records in zone for NSEC")
	}
}

func TestGenerateNSEC3_MalformedParam(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: "NSEC3PARAM", Content: "too short"},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	_, err := srv.generateNSEC3(context.Background(), zone, "test")
	if err == nil {
		t.Errorf("Expected error for malformed NSEC3PARAM")
	}
}

func TestGenerateNSEC3_EmptyHashes(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: "NSEC3PARAM", Content: "1 0 10 ABCD"},
		},
		failListRecords: true, // This will make ListRecordsForZone return an error
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	_, err := srv.generateNSEC3(context.Background(), zone, "test")
	if err == nil {
		t.Errorf("Expected error when no records to hash for NSEC3")
	}
}

func TestGenerateNSEC3_BoundaryWrap(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: "NSEC3PARAM", Content: "1 0 10 -"},
			{ZoneID: "z1", Name: "a.example.com.", Type: domain.TypeA},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	nsec3, err := srv.generateNSEC3(context.Background(), zone, "zzzzzzzz.example.com.")
	if err != nil {
		t.Fatalf("generateNSEC3 failed: %v", err)
	}

	if nsec3.Type != packet.NSEC3 {
		t.Errorf("Expected NSEC3 record")
	}
}

func TestGenerateNSEC3_ExactMatch(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com."},
		},
		records: []domain.Record{
			{ZoneID: "z1", Name: "example.com.", Type: "NSEC3PARAM", Content: "1 0 10 ABCD"},
			{ZoneID: "z1", Name: "www.example.com.", Type: domain.TypeA},
		},
	}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	nsec3, err := srv.generateNSEC3(context.Background(), zone, "www.example.com.")
	if err != nil {
		t.Fatalf("generateNSEC3 failed: %v", err)
	}

	if !strings.HasSuffix(nsec3.Name, ".example.com.") {
		t.Errorf("NSEC3 name should have zone suffix: %s", nsec3.Name)
	}
}

func TestGenerateNSEC_ListError(t *testing.T) {
	repo := &mockServerRepo{failListRecords: true}
	srv := NewServer(":0", repo, nil)
	zone := &domain.Zone{ID: "z1", Name: "example.com."}

	_, err := srv.generateNSEC(context.Background(), zone, "test")
	if err == nil {
		t.Errorf("Expected error when ListRecordsForZone fails")
	}
}

func TestPadResponse_NoOPT(t *testing.T) {
	srv := NewServer(":0", nil, nil)
	resp := packet.NewDNSPacket()
	// No OPT in Resources
	srv.padResponse(resp, 128)
	if len(resp.Resources) != 0 {
		t.Errorf("Expected no changes when OPT is missing")
	}
}

func TestPadResponse_ExactBlockSize(t *testing.T) {
	srv := NewServer(":0", nil, nil)
	resp := packet.NewDNSPacket()
	opt := packet.DNSRecord{Type: packet.OPT, Class: 4096}
	resp.Resources = append(resp.Resources, opt)

	// Header 12 + OPT 11 = 23. Overhead 4 = 27.
	srv.padResponse(resp, 27)
	
	for _, r := range resp.Resources {
		if r.Type == packet.OPT {
			for _, o := range r.Options {
				if o.Code == packet.EdnsOptionPadding {
					if len(o.Data) != 0 {
						t.Errorf("Expected 0 bytes of padding for exact block size match, got %d", len(o.Data))
					}
				}
			}
		}
	}
}
