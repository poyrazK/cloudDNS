// Package domain contains the core domain models for the DNS system.
package domain

import (
	"time"
)

// Role represents a user's authorization level.
type Role string

// Role constants define the authorization levels for API access.
const (
	RoleAdmin  Role = "admin"  // Full CRUD on all zones/records
	RoleWriter Role = "writer"  // CREATE/UPDATE records, no zone/key management
	RoleReader Role = "reader"  // GET-only access
)

// APIKey represents a tenant's API authentication key.
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
