package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

type contextKey string

const (
	CtxTenantID contextKey = "tenant_id"
	CtxRole     contextKey = "role"
)

func AuthMiddleware(repo ports.DNSRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized: missing or invalid authorization header", http.StatusUnauthorized)
				return
			}

			key := strings.TrimPrefix(authHeader, "Bearer ")
			hash := sha256.Sum256([]byte(key))
			keyHash := hex.EncodeToString(hash[:])

			apiKey, err := repo.GetAPIKeyByHash(r.Context(), keyHash)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if apiKey == nil || !apiKey.Active {
				http.Error(w, "Unauthorized: invalid or inactive API key", http.StatusUnauthorized)
				return
			}

			if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
				http.Error(w, "Unauthorized: API key expired", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), CtxTenantID, apiKey.TenantID)
			ctx = context.WithValue(ctx, CtxRole, apiKey.Role)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(roles ...domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(CtxRole).(domain.Role)
			if !ok {
				http.Error(w, "Forbidden: role not found in context", http.StatusForbidden)
				return
			}

			allowed := false
			for _, r := range roles {
				if r == role {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
