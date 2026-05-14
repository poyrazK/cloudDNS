package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
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
	// Set up trusted proxy CIDR for tests
	originalCIDRs := TrustedProxyCIDRs
	defer func() { TrustedProxyCIDRs = originalCIDRs }()
	_, trustedCIDR, _ := net.ParseCIDR("192.168.1.0/24")
	TrustedProxyCIDRs = []*net.IPNet{trustedCIDR}

	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		expected string
	}{
		{
			name:     "X-Real-IP from trusted proxy",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1"},
			remote:   "192.168.1.10:1234", // from trusted proxy
			expected: "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For from trusted proxy",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"},
			remote:   "192.168.1.10:1234",
			expected: "10.0.0.1",
		},
		{
			name:     "Headers ignored from untrusted IP",
			headers:  map[string]string{"X-Real-IP": "10.0.0.1", "X-Forwarded-For": "10.0.0.1"},
			remote:   "10.0.0.1:1234", // not from trusted proxy
			expected: "10.0.0.1",    // should use RemoteAddr
		},
		{
			name:     "No headers, fallback to RemoteAddr",
			headers:  map[string]string{},
			remote:   "192.168.1.1:1234",
			expected: "192.168.1.1",
		},
		{
			name:     "Empty X-Real-IP from trusted, fallback to RemoteAddr",
			headers:  map[string]string{"X-Real-IP": ""},
			remote:   "192.168.1.10:1234",
			expected: "192.168.1.10",
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
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("Rate limited when both limits exhausted", func(t *testing.T) {
		ml := newMultiLimiter()
		middleware := RateLimitMiddleware(ml, categoryRead)
		// Use unique IP not from any trusted proxy
		clientIPValue := "10.0.0.99"

		// Exhaust tenant reads (500 burst) and IP reads (250 burst)
		for i := 0; i < 500; i++ {
			ml.Allow("tenant-test", clientIPValue, categoryRead)
		}
		for i := 0; i < 250; i++ {
			ml.Allow("tenant-test", clientIPValue, categoryRead)
		}

		ctx := context.WithValue(context.Background(), CtxTenantID, "tenant-test")
		req := httptest.NewRequest("GET", "/zones", nil).WithContext(ctx)
		req.RemoteAddr = clientIPValue + ":1234"
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

func TestCORSMiddleware(t *testing.T) {
	t.Run("AllowAllOrigins", func(t *testing.T) {
		config := &CORSConfig{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
			MaxAge:         86400,
		}
		middleware := CORSMiddleware(config)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Origin", "https://example.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("expected *, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("SpecificOrigin", func(t *testing.T) {
		config := &CORSConfig{
			AllowedOrigins: []string{"https://example.com", "https://app.example.org"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
			MaxAge:         86400,
		}
		middleware := CORSMiddleware(config)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Origin", "https://example.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		if rr.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
			t.Errorf("expected https://example.com, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
		}
		if rr.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Errorf("expected true, got %s", rr.Header().Get("Access-Control-Allow-Credentials"))
		}
	})

	t.Run("DisallowedOrigin", func(t *testing.T) {
		config := &CORSConfig{
			AllowedOrigins: []string{"https://allowed.com"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
			MaxAge:         86400,
		}
		middleware := CORSMiddleware(config)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/zones", nil)
		req.Header.Set("Origin", "https://malicious.com")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		if rr.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("expected empty, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("NoOrigin", func(t *testing.T) {
		config := &CORSConfig{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type"},
			MaxAge:         86400,
		}
		middleware := CORSMiddleware(config)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/zones", nil)
		// No Origin header set
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
		// No CORS headers when no origin
		if rr.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("expected empty, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("PreflightOptions", func(t *testing.T) {
		config := &CORSConfig{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Authorization", "Content-Type", "X-Request-ID"},
			MaxAge:         3600,
		}
		middleware := CORSMiddleware(config)
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("OPTIONS", "/zones", nil)
		req.Header.Set("Origin", "https://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d", rr.Code)
		}
		if rr.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
			t.Errorf("expected https://example.com, got %s", rr.Header().Get("Access-Control-Allow-Origin"))
		}
		if rr.Header().Get("Access-Control-Allow-Methods") != "GET, POST, DELETE, OPTIONS" {
			t.Errorf("unexpected Access-Control-Allow-Methods: %s", rr.Header().Get("Access-Control-Allow-Methods"))
		}
		if rr.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, X-Request-ID" {
			t.Errorf("unexpected Access-Control-Allow-Headers: %s", rr.Header().Get("Access-Control-Allow-Headers"))
		}
		if rr.Header().Get("Access-Control-Max-Age") != "3600" {
			t.Errorf("expected 3600, got %s", rr.Header().Get("Access-Control-Max-Age"))
		}
	})
}

func TestDefaultCORSConfig(t *testing.T) {
	t.Run("DefaultEmptyOrigins", func(t *testing.T) {
		// When CORS_ALLOWED_ORIGINS is not set, no origins are allowed (secure default)
		t.Setenv("CORS_ALLOWED_ORIGINS", "")
		config := DefaultCORSConfig()
		if len(config.AllowedOrigins) != 0 {
			t.Errorf("expected empty AllowedOrigins, got %v", config.AllowedOrigins)
		}
		if config.MaxAge != 86400 {
			t.Errorf("expected 86400, got %d", config.MaxAge)
		}
		// Verify no origin is allowed
		if config.isOriginAllowed("https://localhost") {
			t.Errorf("expected localhost to NOT be allowed with empty config")
		}
		if config.isOriginAllowed("*") {
			t.Errorf("expected * to NOT be allowed with empty config")
		}
	})

	t.Run("MultipleOrigins", func(t *testing.T) {
		t.Setenv("CORS_ALLOWED_ORIGINS", "https://a.com,https://b.com,https://c.com")
		config := DefaultCORSConfig()
		if len(config.AllowedOrigins) != 3 {
			t.Errorf("expected 3 origins, got %d", len(config.AllowedOrigins))
		}
	})
}
