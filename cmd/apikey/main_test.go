package main

import (
	"bytes"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/testutil"
	"github.com/stretchr/testify/mock"
)

func TestGenerateKey(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	mockRepo.On("CreateAPIKey", mock.AnythingOfType("*domain.APIKey")).Return(nil)

	out := &bytes.Buffer{}
	err := generateKey(mockRepo, "tenant1", "admin", "test-key", 30, out)

	if err != nil {
		t.Fatalf("generateKey failed: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("API Key Created Successfully!")) {
		t.Errorf("expected success message in output")
	}
	mockRepo.AssertExpectations(t)
}

func TestListKeys(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	keys := []domain.APIKey{
		{ID: "id1", Name: "name1", Role: domain.RoleAdmin, KeyPrefix: "p1", Active: true},
	}
	mockRepo.On("ListAPIKeys", "tenant1").Return(keys, nil)

	out := &bytes.Buffer{}
	err := listKeys(mockRepo, "tenant1", out)

	if err != nil {
		t.Fatalf("listKeys failed: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("id1")) {
		t.Errorf("expected key ID in output")
	}
	mockRepo.AssertExpectations(t)
}

func TestRevokeKey(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	mockRepo.On("DeleteAPIKey", "tenant1", "id1").Return(nil)

	out := &bytes.Buffer{}
	err := revokeKey(mockRepo, "tenant1", "id1", out)

	if err != nil {
		t.Fatalf("revokeKey failed: %v", err)
	}

	if !bytes.Contains(out.Bytes(), []byte("revoked")) {
		t.Errorf("expected revocation message in output")
	}
	mockRepo.AssertExpectations(t)
}

func TestRunCommand(t *testing.T) {
	mockRepo := new(testutil.MockRepo)
	out := &bytes.Buffer{}

	err := run([]string{"apikey"}, out, mockRepo)
	if err == nil || err.Error() != "expected 'create', 'list' or 'revoke' subcommands" {
		t.Errorf("Expected less than 2 args error, got: %v", err)
	}

	err = run([]string{"apikey", "unknown"}, out, mockRepo)
	if err == nil || err.Error() != "unknown subcommand: unknown" {
		t.Errorf("Expected unknown subcommand error, got: %v", err)
	}

	// Test create path
	mockRepo.On("CreateAPIKey", mock.AnythingOfType("*domain.APIKey")).Return(nil).Once()
	err = run([]string{"apikey", "create", "-tenant", "t1", "-role", "admin", "-name", "test", "-days", "30"}, out, mockRepo)
	if err != nil {
		t.Errorf("Unexpected error for create: %v", err)
	}

	// Test list path
	keys := []domain.APIKey{
		{ID: "id1", Name: "name1", Role: domain.RoleAdmin, KeyPrefix: "p1", Active: true},
	}
	mockRepo.On("ListAPIKeys", "t2").Return(keys, nil).Once()
	err = run([]string{"apikey", "list", "-tenant", "t2"}, out, mockRepo)
	if err != nil {
		t.Errorf("Unexpected error for list: %v", err)
	}

	// Test revoke path
	mockRepo.On("DeleteAPIKey", "default-tenant", "id1").Return(nil).Once()
	err = run([]string{"apikey", "revoke", "-id", "id1"}, out, mockRepo)
	if err != nil {
		t.Errorf("Unexpected error for revoke: %v", err)
	}
}
