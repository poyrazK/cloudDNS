// Package domain contains the core business logic and entities for cloudDNS.
package domain

import (
	"time"
)

// RecordType represents the type of a DNS record (e.g., A, AAAA, MX).
type RecordType string

const (
	// TypeA represents an IPv4 address record.
	TypeA RecordType = "A"
	// TypeAAAA represents an IPv6 address record.
	TypeAAAA RecordType = "AAAA"
	// TypeCNAME represents a canonical name record.
	TypeCNAME RecordType = "CNAME"
	// TypeMX represents a mail exchange record.
	TypeMX RecordType = "MX"
	// TypeTXT represents a text record.
	TypeTXT RecordType = "TXT"
	// TypeNS represents a name server record.
	TypeNS RecordType = "NS"
	// TypeSOA represents a start of authority record.
	TypeSOA RecordType = "SOA"
	// TypePTR represents a pointer record.
	TypePTR RecordType = "PTR"
	// TypeSRV represents a service locator record (RFC 2782).
	TypeSRV RecordType = "SRV"
)

// Zone represents a DNS zone.
type Zone struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"` // e.g., example.com.
	VPCID       *string   `json:"vpc_id,omitempty"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Record represents a DNS resource record within a zone.
type Record struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	ZoneID    string     `json:"zone_id"`
	Name      string     `json:"name"` // e.g., www
	Type      RecordType `json:"type"`
	Content   string     `json:"content"`
	TTL       int        `json:"ttl"`
	Priority  *int       `json:"priority,omitempty"` // For MX, SRV records
	Weight    *int       `json:"weight,omitempty"`   // For SRV records
	Port      *int       `json:"port,omitempty"`     // For SRV records
	Network   *string    `json:"network,omitempty"`  // CIDR or Scope (e.g., "10.0.0.0/8" or "public")
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// ZoneChange represents a historical change to a DNS zone, used for IXFR and auditing.
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
	Weight    *int       `json:"weight,omitempty"`
	Port      *int       `json:"port,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// AuditLog records administrative actions performed on the DNS system.
type AuditLog struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Action       string    `json:"action"`        // e.g., "CREATE_RECORD", "DELETE_ZONE"
	ResourceType string    `json:"resource_type"` // e.g., "ZONE", "RECORD"
	ResourceID   string    `json:"resource_id"`
	Details      string    `json:"details"` // JSON or string description
	CreatedAt    time.Time `json:"created_at"`
}

// DNSSECKey represents a cryptographic key used for DNSSEC signing.
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
