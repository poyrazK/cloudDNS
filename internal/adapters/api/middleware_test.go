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
		w.Header().Set("X-Tenant-Id", tenantID)
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
		if rr.Header().Get("X-Tenant-Id") != "my-tenant" {
			t.Errorf("expected tenant ID 'my-tenant', got %s", rr.Header().Get("X-Tenant-Id"))
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

func TestClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		expected string
	}{
		{
			name:     "X-Real-IP preferred",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1"},
			remote:   "192.168.1.1:1234",
			expected: "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For first value",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"},
			remote:   "192.168.1.1:1234",
			expected: "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For single value",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remote:   "192.168.1.1:1234",
			expected: "10.0.0.1",
		},
		{
			name:     "No headers, fallback to RemoteAddr",
			headers:  map[string]string{},
			remote:   "192.168.1.1:1234",
			expected: "192.168.1.1",
		},
		{
			name:     "Empty X-Real-IP, fallback to RemoteAddr",
			headers:  map[string]string{"X-Real-IP": ""},
			remote:   "192.168.1.1:1234",
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.RemoteAddr = tt.remote

			got := clientIP(req)
			if got != tt.expected {
				t.Errorf("clientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	ml := newMultiLimiter()

	t.Run("Allowed when under limit", func(t *testing.T) {
		middleware := RateLimitMiddleware(ml, categoryRead)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		ctx := context.WithValue(context.Background(), CtxTenantID, "tenant-test")
		req := httptest.NewRequest("GET", "/zones", nil).WithContext(ctx)
		req.Header.Set("X-Real-IP", "10.0.0.1")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("Rate limited when tenant exhausted", func(t *testing.T) {
		ml := newMultiLimiter()
		middleware := RateLimitMiddleware(ml, categoryRead)
		clientIP := "10.0.0.2"

		// Exhaust tenant reads (500 burst) and IP reads (250 burst)
		for i := 0; i < 500; i++ {
			ml.Allow("tenant-test", clientIP, categoryRead)
		}
		for i := 0; i < 250; i++ {
			ml.Allow("tenant-test", clientIP, categoryRead)
		}

		ctx := context.WithValue(context.Background(), CtxTenantID, "tenant-test")
		req := httptest.NewRequest("GET", "/zones", nil).WithContext(ctx)
		req.Header.Set("X-Real-IP", clientIP)
		rr := httptest.NewRecorder()
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", rr.Code)
		}
	})
}
