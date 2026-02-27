package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/testutil"
)

func TestAuthMiddleware(t *testing.T) {
	mockRepo := &testutil.MockRepo{}
	middleware := AuthMiddleware(mockRepo)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, _ := r.Context().Value(CtxTenantID).(string)
		w.Header().Set("X-Tenant-ID", tenantID)
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Missing Authorization Header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/zones", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("Invalid Key", func(t *testing.T) {
		rawKey := "cdns_invalidkey"
		hash := sha256.Sum256([]byte(rawKey))
		keyHash := hex.EncodeToString(hash[:])

		mockRepo.On("GetAPIKeyByHash", keyHash).Return(nil, nil).Once()

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Authorization", "Bearer "+rawKey)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("Valid Key", func(t *testing.T) {
		rawKey := "cdns_validkey"
		hash := sha256.Sum256([]byte(rawKey))
		keyHash := hex.EncodeToString(hash[:])

		apiKey := &domain.APIKey{
			TenantID: "my-tenant",
			Role:     domain.RoleAdmin,
			Active:   true,
		}
		mockRepo.On("GetAPIKeyByHash", keyHash).Return(apiKey, nil).Once()

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Authorization", "Bearer "+rawKey)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		if rr.Header().Get("X-Tenant-ID") != "my-tenant" {
			t.Errorf("expected tenant ID 'my-tenant', got %s", rr.Header().Get("X-Tenant-ID"))
		}
	})

	t.Run("Expired Key", func(t *testing.T) {
		rawKey := "cdns_expiredkey"
		hash := sha256.Sum256([]byte(rawKey))
		keyHash := hex.EncodeToString(hash[:])

		expired := time.Now().Add(-1 * time.Hour)
		apiKey := &domain.APIKey{
			TenantID:  "my-tenant",
			Role:      domain.RoleAdmin,
			Active:    true,
			ExpiresAt: &expired,
		}
		mockRepo.On("GetAPIKeyByHash", keyHash).Return(apiKey, nil).Once()

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Authorization", "Bearer "+rawKey)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("Inactive Key", func(t *testing.T) {
		rawKey := "cdns_inactivekey"
		hash := sha256.Sum256([]byte(rawKey))
		keyHash := hex.EncodeToString(hash[:])

		mockRepo.On("GetAPIKeyByHash", keyHash).Return(&domain.APIKey{Active: false, TenantID: "t"}, nil).Once()

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Authorization", "Bearer "+rawKey)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("Repository Error", func(t *testing.T) {
		rawKey := "cdns_db_err"
		hash := sha256.Sum256([]byte(rawKey))
		keyHash := hex.EncodeToString(hash[:])

		mockRepo.On("GetAPIKeyByHash", keyHash).Return((*domain.APIKey)(nil), errors.New("db error")).Once()

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Authorization", "Bearer "+rawKey)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rr.Code)
		}
	})
}

func TestRequireRole(t *testing.T) {
	adminOnly := RequireRole(domain.RoleAdmin)
	handler := adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Admin Role Allowed", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), CtxRole, domain.RoleAdmin)
		req := httptest.NewRequest("POST", "/zones", nil).WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("Reader Role Forbidden", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), CtxRole, domain.RoleReader)
		req := httptest.NewRequest("POST", "/zones", nil).WithContext(ctx)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}
