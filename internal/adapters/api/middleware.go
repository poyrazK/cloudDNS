package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

type contextKey string

// CtxTenantID is the context key for the tenant ID extracted from the API key.
const CtxTenantID contextKey = "tenant_id"
// CtxRole is the context key for the role extracted from the API key.
const CtxRole contextKey = "role"

// TrustedProxyCIDRs contains CIDR ranges for trusted proxies.
// If set, only requests from these IPs will have X-Real-IP/X-Forwarded-For honored.
var TrustedProxyCIDRs []*net.IPNet

// isFromTrustedProxy returns true if the remote address is from a trusted proxy.
func isFromTrustedProxy(remoteAddr string) bool {
	if len(TrustedProxyCIDRs) == 0 {
		return false
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, cidr := range TrustedProxyCIDRs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// CORSConfig holds CORS settings from environment.
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
}

// DefaultCORSConfig creates config from CORS_ALLOWED_ORIGINS env var (comma-separated, or "*" for all).
func DefaultCORSConfig() *CORSConfig {
	origins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if origins == "" {
		origins = "*"
	}
	return &CORSConfig{
		AllowedOrigins: strings.Split(origins, ","),
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "X-Real-IP", "X-Forwarded-For"},
		MaxAge:         86400,
	}
}

// isOriginAllowed checks if the origin is allowed.
func (c *CORSConfig) isOriginAllowed(origin string) bool {
	for _, allowed := range c.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

// CORSMiddleware returns middleware that adds CORS headers.
func CORSMiddleware(config *CORSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Set CORS headers for allowed origins
			if config.isOriginAllowed(origin) {
				if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					// Credentials header required for specific origins (not wildcard)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			// Handle preflight OPTIONS
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware validates API keys and injects tenant context into requests.
func AuthMiddleware(repo ports.DNSRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized: missing or invalid authorization header", http.StatusUnauthorized)
				return
			}

			key := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if key == "" {
				http.Error(w, "Unauthorized: missing or invalid authorization header", http.StatusUnauthorized)
				return
			}
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

// RequireRole returns middleware that restricts access to users with one of the given roles.
func RequireRole(roles ...domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(CtxRole).(domain.Role)
			if !ok {
				http.Error(w, "Forbidden: role not found in context", http.StatusForbidden)
				return
			}

			allowed := false
			for _, allowedRole := range roles {
				if allowedRole == role {
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

// RateLimitMiddleware creates middleware that applies per-tenant and per-IP rate limiting.
// Pass a pointer to the multiLimiter from the Handler and the endpoint category.
func RateLimitMiddleware(ml *multiLimiter, cat endpointCategory) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, _ := r.Context().Value(CtxTenantID).(string)
			ip := clientIP(r)

			if tenantID == "" {
				slog.Warn("rate limit: empty tenant ID in context",
					"ip", ip,
					"category", cat,
					"path", r.URL.Path,
				)
			}

			if !ml.Allow(tenantID, ip, cat) {
				http.Error(w, "Too Many Requests: rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP address from the request.
// It only uses X-Real-IP/X-Forwarded-For headers if the request comes from a trusted proxy.
func clientIP(r *http.Request) string {
	// Only honor headers from trusted proxies
	if isFromTrustedProxy(r.RemoteAddr) {
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			return realIP
		}
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if idx := strings.Index(fwd, ","); idx != -1 {
				fwd = fwd[:idx]
			}
			return strings.TrimSpace(fwd)
		}
	}
	// Fall back to remote address
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
