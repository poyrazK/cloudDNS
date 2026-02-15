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
// It implements Automated Key Rollover using a Double-Signature orchestration pattern.
func (s *DNSSECService) AutomateLifecycle(ctx context.Context, zoneID string) error {
	keys, err := s.repo.ListKeysForZone(ctx, zoneID)
	if err != nil {
		return err
	}

	const (
		ZSKRolloverPeriod = 30 * 24 * time.Hour
		ZSKOverlapPeriod  = 1 * 24 * time.Hour
		KSKRolloverPeriod = 365 * 24 * time.Hour
		KSKOverlapPeriod  = 2 * 24 * time.Hour
	)

	processType := func(keyType string, rollover, overlap time.Duration) error {
		var activeKeys []domain.DNSSECKey
		for _, k := range keys {
			if k.KeyType == keyType && k.Active {
				activeKeys = append(activeKeys, k)
			}
		}

		// 1. Initial creation
		if len(activeKeys) == 0 {
			_, errCreate := s.GenerateKey(ctx, zoneID, keyType)
			return errCreate
		}

		// 2. Rollover Orchestration
		now := time.Now()
		hasRecentKey := false
		for _, k := range activeKeys {
			if now.Sub(k.CreatedAt) < rollover {
				hasRecentKey = true
			}
		}

		// If no key is recent, we need a new one
		if !hasRecentKey {
			_, errGen := s.GenerateKey(ctx, zoneID, keyType)
			return errGen // Return the error if generation fails
		}

		// 3. Phase out old keys
		for _, k := range activeKeys {
			age := now.Sub(k.CreatedAt)
			if age > rollover+overlap {
				k.Active = false
				k.UpdatedAt = now
				if errUpd := s.repo.UpdateKey(ctx, &k); errUpd != nil {
					return errUpd
				}
			}
		}
		return nil
	}

	if err := processType("KSK", KSKRolloverPeriod, KSKOverlapPeriod); err != nil {
		return err
	}
	if err := processType("ZSK", ZSKRolloverPeriod, ZSKOverlapPeriod); err != nil {
		return err
	}

	return nil
}

// GetActiveKeys returns all currently active keys of a specific type for a zone
func (s *DNSSECService) GetActiveKeys(ctx context.Context, zoneID string, keyType string) ([]domain.DNSSECKey, error) {
	keys, err := s.repo.ListKeysForZone(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	var active []domain.DNSSECKey
	for _, k := range keys {
		if k.KeyType == keyType && k.Active {
			active = append(active, k)
		}
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("no active %s key found", keyType)
	}
	return active, nil
}

// SignRRSet signs a list of packet records using all active ZSKs for the zone
func (s *DNSSECService) SignRRSet(ctx context.Context, zoneName string, zoneID string, records []packet.DNSRecord) ([]packet.DNSRecord, error) {
	if len(records) == 0 {
		return nil, nil
	}

	keys, err := s.GetActiveKeys(ctx, zoneID, "ZSK")
	if err != nil {
		return nil, err
	}

	var sigs []packet.DNSRecord
	for _, key := range keys {
		priv, err := x509.ParseECPrivateKey(key.PrivateKey)
		if err != nil {
			return nil, err
		}

		// Calculate key tag
		tempKeyRec := packet.DNSRecord{
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
		sigs = append(sigs, sig)
	}

	return sigs, nil
}
