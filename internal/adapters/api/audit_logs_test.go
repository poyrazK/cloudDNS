package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/testutil"
)

func TestListAuditLogs(t *testing.T) {
	svc := &mockDNSService{}
	repo := &testutil.MockRepo{}
	handler := NewAPIHandler(svc, repo)

	req := httptest.NewRequest("GET", "/audit-logs", nil)
	ctx := context.WithValue(req.Context(), CtxTenantID, "t1")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ListAuditLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var logs []domain.AuditLog
	if err := json.NewDecoder(w.Body).Decode(&logs); err != nil {
		t.Fatalf("Failed to decode logs: %v", err)
	}

	if len(logs) != 1 || logs[0].TenantID != "t1" {
		t.Errorf("Unexpected logs: %+v", logs)
	}
}
