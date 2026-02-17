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
	TypePTR   RecordType = "PTR"
	TypeSRV   RecordType = "SRV"
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
	Weight    *int       `json:"weight,omitempty"`  // SRV
	Port      *int       `json:"port,omitempty"`    // SRV
	Network   *string    `json:"network,omitempty"` // CIDR or Scope (e.g., "10.0.0.0/8" or "public")
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type ZoneChange struct {
	ID        string     `json:"id"`
	ZoneID    string     `json:"zone_id"`
	Serial    uint32     `json:"serial"`
	Action    string     `json:"action"` // "ADD" or "DELETE"
	Name      string     `json:"name"`
	Type      RecordType `json:"type"`
	Content   string     `json:"content"`
	TTL       int        `json:"ttl"`
	Priority  *int       `json:"priority,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
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

type DNSSECKey struct {
	ID         string    `json:"id"`
	ZoneID     string    `json:"zone_id"`
	KeyType    string    `json:"key_type"` // "KSK" or "ZSK"
	Algorithm  int       `json:"algorithm"`
	PrivateKey []byte    `json:"-"`
	PublicKey  []byte    `json:"public_key"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
