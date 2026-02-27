package domain

import (
	"time"
)

type Role string

const (
	RoleAdmin  Role = "admin"  // Full CRUD on all zones/records
	RoleReader Role = "reader" // GET-only access
)

type APIKey struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`       // Human-readable label, e.g. "ci-deploy-key"
	KeyHash   string     `json:"-"`          // SHA-256 hash of the key (never store raw)
	KeyPrefix string     `json:"key_prefix"` // First 8 chars for identification
	Role      Role       `json:"role"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
