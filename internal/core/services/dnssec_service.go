// Package services implements the core business logic for cloudDNS.
package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// DNSSECService provides functionality for managing DNSSEC keys and signing RRsets.
type DNSSECService struct {
	repo   ports.DNSRepository
	logger *slog.Logger
	keyCache sync.Map  // zoneID -> *cachedKeys
}

// cachedKeys holds parsed ECDSA keys for a zone with TTL.
type cachedKeys struct {
	keys    map[string][]*ecdsa.PrivateKey  // keyType -> parsed keys
	keyTags map[string][]uint16              // keyType -> key tags (pre-computed)
	expires time.Time
}

// cachedSigningKey holds a parsed key and its pre-computed key tag for signing.
type cachedSigningKey struct {
	privateKey *ecdsa.PrivateKey
	keyTag     uint16
}

// keyCacheTTL is the TTL for cached DNSSEC keys.
const keyCacheTTL = 5 * time.Minute

// NewDNSSECService creates and returns a new DNSSECService instance.
func NewDNSSECService(repo ports.DNSRepository) *DNSSECService {
	return &DNSSECService{repo: repo, logger: slog.Default()}
}

// GenerateKey creates a new ECDSA P-256 key pair for a zone
func (s *DNSSECService) GenerateKey(ctx context.Context, zoneID string, keyType string) (*domain.DNSSECKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
	}

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

	// Invalidate cached keys for this zone since we added a new key
	s.InvalidateKeyCache(zoneID)

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
				// Invalidate cache since a key was deactivated
				s.InvalidateKeyCache(zoneID)
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

	// Try cache first
	if cached := s.getCachedKeys(zoneID, "ZSK"); cached != nil {
		return s.signWithKeys(ctx, zoneName, records, cached)
	}

	// Cache miss: fetch from DB
	keys, err := s.GetActiveKeys(ctx, zoneID, "ZSK")
	if err != nil {
		return nil, err
	}

	// Parse keys
	parsedKeys := make([]*ecdsa.PrivateKey, 0, len(keys))
	keyTags := make([]uint16, 0, len(keys))
	for _, key := range keys {
		priv, err := x509.ParseECPrivateKey(key.PrivateKey)
		if err != nil {
			return nil, err
		}
		parsedKeys = append(parsedKeys, priv)
		// Pre-compute key tag
		pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		tempKeyRec := packet.DNSRecord{
			Type:      packet.DNSKEY,
			Flags:     256,
			Algorithm: 13,
			PublicKey: pubBytes,
		}
		keyTags = append(keyTags, tempKeyRec.ComputeKeyTag())
	}
	s.cacheKeys(zoneID, "ZSK", parsedKeys, keyTags)

	// Build signing keys with pre-computed tags
	signingKeys := make([]*cachedSigningKey, 0, len(parsedKeys))
	for i := range parsedKeys {
		signingKeys = append(signingKeys, &cachedSigningKey{privateKey: parsedKeys[i], keyTag: keyTags[i]})
	}

	return s.signWithKeys(ctx, zoneName, records, signingKeys)
}

// signWithKeys signs records using the provided cached signing keys (with pre-computed key tags).
func (s *DNSSECService) signWithKeys(_ context.Context, zoneName string, records []packet.DNSRecord, keys []*cachedSigningKey) ([]packet.DNSRecord, error) {
	sigs := make([]packet.DNSRecord, 0, len(keys))
	for _, k := range keys {
		// Calculate inception and expiration (valid for 30 days)
		unixNow := time.Now().Unix()
		now := uint32(0)
		if unixNow >= 0 && unixNow <= math.MaxUint32 {
			now = uint32(unixNow) // #nosec G115
		}
		ttl := uint64(30 * 24 * 60 * 60)
		exp := uint64(now) + ttl
		if exp > math.MaxUint32 {
			exp = math.MaxUint32
		}
		expiration := uint32(exp)

		sig, err := packet.SignRRSet(records, k.privateKey, packet.AlgorithmECDSAP256, zoneName, k.keyTag, now, expiration)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}

	return sigs, nil
}

// getCachedKeys returns cached parsed keys for a zone if not expired.
func (s *DNSSECService) getCachedKeys(zoneID, keyType string) []*cachedSigningKey {
	val, ok := s.keyCache.Load(zoneID)
	if !ok {
		return nil
	}
	cached := val.(*cachedKeys)
	if time.Now().After(cached.expires) {
		s.keyCache.Delete(zoneID)
		return nil
	}
	tags := cached.keyTags[keyType]
	keys := cached.keys[keyType]
	result := make([]*cachedSigningKey, 0, len(keys))
	for i := range keys {
		result = append(result, &cachedSigningKey{privateKey: keys[i], keyTag: tags[i]})
	}
	return result
}

// cacheKeys stores parsed keys in the cache with TTL, merging with existing keys for the zone.
// keyTags must be provided and have the same length as keys.
// Atomically replaces the entire cachedKeys entry so readers always see a consistent snapshot.
func (s *DNSSECService) cacheKeys(zoneID, keyType string, keys []*ecdsa.PrivateKey, keyTags []uint16) {
	existing, _ := s.keyCache.Load(zoneID)
	ec := &cachedKeys{
		keys:    make(map[string][]*ecdsa.PrivateKey),
		keyTags: make(map[string][]uint16),
		expires: time.Now().Add(keyCacheTTL),
	}
	if existing != nil {
		old := existing.(*cachedKeys)
		for k, v := range old.keys {
			ec.keys[k] = v
		}
		for k, v := range old.keyTags {
			ec.keyTags[k] = v
		}
	}
	ec.keys[keyType] = keys
	ec.keyTags[keyType] = keyTags
	s.keyCache.Store(zoneID, ec)
}

// InvalidateKeyCache removes cached keys for a zone.
func (s *DNSSECService) InvalidateKeyCache(zoneID string) {
	s.keyCache.Delete(zoneID)
}

// KeyStats holds DNSSEC key statistics for metrics.
type KeyStats struct {
	ZoneID     string
	ZoneName   string
	KeyType    string
	Algorithm  int
	AgeSeconds float64
}

// CollectKeyStats returns statistics for all active DNSSEC keys.
// Used by the metrics collector to update DNSSEC key age metrics.
func (s *DNSSECService) CollectKeyStats(ctx context.Context) ([]KeyStats, error) {
	zones, err := s.repo.ListZones(ctx, "")
	if err != nil {
		return nil, err
	}

	var stats []KeyStats
	now := time.Now()
	for _, zone := range zones {
		keys, err := s.repo.ListKeysForZone(ctx, zone.ID)
		if err != nil {
			s.logger.Debug("failed to list keys for zone", "zone", zone.Name, "error", err)
			continue
		}
		for _, k := range keys {
			if !k.Active {
				continue
			}
			stats = append(stats, KeyStats{
				ZoneID:     zone.ID,
				ZoneName:   zone.Name,
				KeyType:    strings.ToLower(k.KeyType),
				Algorithm:  k.Algorithm,
				AgeSeconds: now.Sub(k.CreatedAt).Seconds(),
			})
		}
	}
	return stats, nil
}
