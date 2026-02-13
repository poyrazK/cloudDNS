package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type DNSSECService struct {
	repo ports.DNSRepository
}

func NewDNSSECService(repo ports.DNSRepository) *DNSSECService {
	return &DNSSECService{repo: repo}
}

// GenerateKey creates a new ECDSA P-256 key pair for a zone
func (s *DNSSECService) GenerateKey(ctx context.Context, zoneID string, keyType string) (*domain.DNSSECKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)

	key := &domain.DNSSECKey{
		ID:         uuid.New().String(),
		ZoneID:     zoneID,
		KeyType:    keyType,
		Algorithm:  13, // ECDSAP256SHA256
		PrivateKey: privBytes,
		PublicKey:  pubBytes,
		Active:     true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.repo.CreateKey(ctx, key); err != nil {
		return nil, err
	}

	return key, nil
}

// AutomateLifecycle is a background-friendly method to ensure a zone is correctly signed
func (s *DNSSECService) AutomateLifecycle(ctx context.Context, zoneID string) error {
	keys, err := s.repo.ListKeysForZone(ctx, zoneID)
	if err != nil {
		return err
	}

	// 1. Ensure we have at least one KSK and one ZSK
	hasKSK := false
	hasZSK := false
	for _, k := range keys {
		if k.KeyType == "KSK" && k.Active { hasKSK = true }
		if k.KeyType == "ZSK" && k.Active { hasZSK = true }
	}

	if !hasKSK {
		_, err = s.GenerateKey(ctx, zoneID, "KSK")
		if err != nil { return err }
	}
	if !hasZSK {
		_, err = s.GenerateKey(ctx, zoneID, "ZSK")
		if err != nil { return err }
	}

	// 2. Check for signature expiration (Simplified)
	// In a real implementation, we would query current RRSIGs and re-sign if expiring within 3 days.
	
	return nil
}

// GetActiveKey returns the current active key of a specific type for a zone
func (s *DNSSECService) GetActiveKey(ctx context.Context, zoneID string, keyType string) (*domain.DNSSECKey, error) {
	keys, err := s.repo.ListKeysForZone(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if k.KeyType == keyType && k.Active {
			return &k, nil
		}
	}
	return nil, fmt.Errorf("no active %s key found", keyType)
}

// SignRRSet signs a list of packet records using the active ZSK for the zone
func (s *DNSSECService) SignRRSet(ctx context.Context, zoneName string, zoneID string, records []packet.DnsRecord) (*packet.DnsRecord, error) {
	if len(records) == 0 {
		return nil, nil
	}

	key, err := s.GetActiveKey(ctx, zoneID, "ZSK")
	if err != nil {
		return nil, err
	}

	priv, err := x509.ParseECPrivateKey(key.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Calculate key tag
	tempKeyRec := packet.DnsRecord{
		Type:      packet.DNSKEY,
		Flags:     256, // ZSK
		Algorithm: 13,
		PublicKey: key.PublicKey,
	}
	keyTag := tempKeyRec.ComputeKeyTag()

	// Calculate inception and expiration (valid for 30 days)
	now := uint32(time.Now().Unix())
	expiration := now + (30 * 24 * 60 * 60)

	sig, err := packet.SignRRSet(records, priv, zoneName, keyTag, now, expiration)
	if err != nil {
		return nil, err
	}

	return &sig, nil
}
