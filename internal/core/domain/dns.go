package domain

import (
	"time"
)

type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeSOA   RecordType = "SOA"
)

type Zone struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"` // e.g., example.com.
	VPCID       *string   `json:"vpc_id,omitempty"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Record struct {
	ID        string     `json:"id"`
	ZoneID    string     `json:"zone_id"`
	Name      string     `json:"name"` // e.g., www
	Type      RecordType `json:"type"`
	Content   string     `json:"content"`
	TTL       int        `json:"ttl"`
	Priority  *int       `json:"priority,omitempty"`
	Network   *string    `json:"network,omitempty"` // CIDR or Scope (e.g., "10.0.0.0/8" or "public")
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type AuditLog struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Action     string    `json:"action"`      // e.g., "CREATE_RECORD", "DELETE_ZONE"
	ResourceType string  `json:"resource_type"` // e.g., "ZONE", "RECORD"
	ResourceID string    `json:"resource_id"`
	Details    string    `json:"details"`     // JSON or string description
	CreatedAt  time.Time `json:"created_at"`
}
