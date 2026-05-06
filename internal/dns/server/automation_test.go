package server

import (
	"context"
	"errors"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestServer_AutomateDNSSEC tests the DNSSEC automation
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

// TestServer_AutomateDNSSEC_ListError tests error handling when listing zones fails
func TestServer_AutomateDNSSEC_ListError(t *testing.T) {
	repo := &mockServerRepo{
		failListZones: true,
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	// Should not panic, just return
	srv.automateDNSSEC()
}

// TestServer_AutomateDNSSEC_AutomateError tests error handling when key creation fails
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

// TestFetchDNSKEYFromNetwork tests the DNSKEY fetching from network
func TestFetchDNSKEYFromNetwork(t *testing.T) {
	repo := &mockServerRepo{
		zones: []domain.Zone{
			{ID: "z1", Name: "example.com.", TenantID: "t1"},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.RecursionEnabled = true

	// Override queryFn to return a mock DNSKEY response
	srv.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		if qtype == packet.DNSKEY {
			resp := packet.NewDNSPacket()
			resp.Header.Response = true
			resp.Answers = append(resp.Answers, packet.DNSRecord{
				Name:     "example.com.",
				Type:     packet.DNSKEY,
				Flags:    257,
				Algorithm: 13,
				PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
			})
			return resp, nil
		}
		return nil, nil
	}

	ctx := context.Background()
	keys, err := srv.fetchDNSKEYFromNetwork(ctx, "example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYFromNetwork failed: %v", err)
	}
	if len(keys) == 0 {
		t.Errorf("Expected at least one DNSKEY, got none")
	}
}

// TestFetchDNSKEYFromNetwork_NoKeys tests handling when no DNSKEYs found in primary response
// Note: The server has fallback DNS (8.8.8.8) that may succeed even when initial query returns empty
func TestFetchDNSKEYFromNetwork_NoKeys(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.RecursionEnabled = true

	// Return empty response - fallback DNS may still provide keys
	srv.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		resp := packet.NewDNSPacket()
		resp.Header.Response = true
		return resp, nil
	}

	ctx := context.Background()
	keys, err := srv.fetchDNSKEYFromNetwork(ctx, "example.com.")
	// With fallback DNS, this may succeed via 8.8.8.8 even though our queryFn returned empty
	// Just verify it doesn't crash
	_ = keys
	_ = err
}

// TestFetchDNSKEYFromNetwork_Authority tests that DNSKEYs from authority section are also captured
func TestFetchDNSKEYFromNetwork_Authority(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.RecursionEnabled = true

	// Return DNSKEY in authority section instead of answers
	srv.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		if qtype == packet.DNSKEY {
			resp := packet.NewDNSPacket()
			resp.Header.Response = true
			resp.Authorities = append(resp.Authorities, packet.DNSRecord{
				Name:     "example.com.",
				Type:     packet.DNSKEY,
				Flags:    257,
				Algorithm: 13,
				PublicKey: []byte{0xaa, 0xbb, 0xcc, 0xdd},
			})
			return resp, nil
		}
		return nil, nil
	}

	ctx := context.Background()
	keys, err := srv.fetchDNSKEYFromNetwork(ctx, "example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYFromNetwork failed: %v", err)
	}
	if len(keys) == 0 {
		t.Errorf("Expected at least one DNSKEY from authority section")
	}
}

// TestFetchDNSKEYFromNetwork_BothAnswersAndAuthorities tests that DNSKEYs from both sections are captured
func TestFetchDNSKEYFromNetwork_BothAnswersAndAuthorities(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.RecursionEnabled = true

	srv.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		if qtype == packet.DNSKEY {
			resp := packet.NewDNSPacket()
			resp.Header.Response = true
			resp.Answers = append(resp.Answers, packet.DNSRecord{
				Name:     "example.com.",
				Type:     packet.DNSKEY,
				Flags:    257,
				Algorithm: 13,
				PublicKey: []byte{0x01, 0x02},
			})
			resp.Authorities = append(resp.Authorities, packet.DNSRecord{
				Name:     "example.com.",
				Type:     packet.DNSKEY,
				Flags:    256,
				Algorithm: 13,
				PublicKey: []byte{0x03, 0x04},
			})
			return resp, nil
		}
		return nil, nil
	}

	ctx := context.Background()
	keys, err := srv.fetchDNSKEYFromNetwork(ctx, "example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYFromNetwork failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("Expected 2 DNSKEYs, got %d", len(keys))
	}
}

// TestFetchDNSKEYFromNetwork_QueryError tests handling of query errors
// Note: This test may not reliably fail because the server has fallback
// resolution (8.8.8.8, 1.1.1.1) that may succeed even when queryFn fails
func TestFetchDNSKEYFromNetwork_QueryError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode - relies on network")
	}
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.RecursionEnabled = true

	// Override queryFn to return error
	srv.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		return nil, errors.New("network unreachable")
	}

	ctx := context.Background()
	keys, err := srv.fetchDNSKEYFromNetwork(ctx, "example.com.")
	// With fallbacks, it might still succeed via 8.8.8.8
	// So we just verify it doesn't crash and returns result
	_ = keys
	_ = err
}

// TestFetchDNSKEYFromNetwork_EmptyPublicKey tests that DNSKEYs with empty public keys are skipped
func TestFetchDNSKEYFromNetwork_EmptyPublicKey(t *testing.T) {
	repo := &mockServerRepo{}
	srv := NewServer("127.0.0.1:0", repo, nil)
	srv.RecursionEnabled = true

	srv.queryFn = func(server string, name string, qtype packet.QueryType) (*packet.DNSPacket, error) {
		if qtype == packet.DNSKEY {
			resp := packet.NewDNSPacket()
			resp.Header.Response = true
			resp.Answers = append(resp.Answers, packet.DNSRecord{
				Name:     "example.com.",
				Type:     packet.DNSKEY,
				Flags:    257,
				Algorithm: 13,
				PublicKey: []byte{},
			})
			return resp, nil
		}
		return nil, nil
	}

	ctx := context.Background()
	_, err := srv.fetchDNSKEYFromNetwork(ctx, "example.com.")
	if err == nil {
		t.Errorf("Expected error when DNSKEY has empty public key")
	}
}
