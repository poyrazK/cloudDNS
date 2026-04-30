// Package services implements the core business logic for cloudDNS.
package services

import (
	"errors"
	"fmt"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// DNSSECValidator validates DNSSEC signatures and trust chains.
type DNSSECValidator struct {
	trustAnchors map[string]packet.DNSRecord // zone -> DNSKEY
}

// NewDNSSECValidator creates a new DNSSECValidator with the given trust anchors.
func NewDNSSECValidator(trustAnchors map[string]packet.DNSRecord) *DNSSECValidator {
	return &DNSSECValidator{
		trustAnchors: trustAnchors,
	}
}

// EDE represents an Extended DNS Error (RFC 8914).
type EDE struct {
	Code   uint16
	Info   string
}

// RFC 8914 Extended DNS Error Codes
const (
	EDECodeOther                  uint16 = 0  // Other Error
	EDECodeUnsupportedDNSKEYAlgo   uint16 = 1  // Unsupported DNSKEY Algorithm
	EDECodeUnsupportedDSDigest     uint16 = 2  // Unsupported DS Digest Type (reused for signature errors)
	EDECodeStaleAnswer           uint16 = 3  // Stale Answer
	EDECodeForgedAnswer          uint16 = 4  // Forged Answer
	EDECodeIndeterminate         uint16 = 5  // DNSSEC Indeterminate
	EDECodeBogus                 uint16 = 6  // DNSSEC Bogus (also used for dnskey-missing)
	EDECodeSignatureExpired      uint16 = 7  // Signature Expired
	EDECodeSignatureNotYetValid  uint16 = 8  // Signature Not Yet Valid
	EDECodeDNSKEYMissing         uint16 = 9  // DNSKEY Missing
	EDECodeDSMissing            uint16 = 10 // DS Missing
	EDECodeNoZoneKeyBitSet       uint16 = 11 // No Zone Key Bit Set
	EDECodeSignatureUnsupported  uint16 = 12 // Signature Unsupported Algorithm
	EDECodeDNSKEYNotAnchor       uint16 = 13 // DNSKEY Not Anchor
	EDECodeTrustAnchorUnknown    uint16 = 17 // Trust Anchor Unknown
	EDECodeExpectedAnswerAfterDNL  uint16 = 18 // Expected Answer After DNL
	EDECodeDelegationNotServed   uint16 = 20 // Delegation Not Served
	EDECodeTTLMismatch          uint16 = 21 // TTL Mismatch
	EDECodeCachedValidatedResponse uint16 = 22 // Cached Validated Response
	// NSEC3-specific (not defined in RFC 8914, using high values to avoid future conflicts)
	EDECodeNSEC3HashAlgoUnsupported uint16 = 23 // NSEC3 hash algorithm not supported
	EDECodeNSEC3InvalidProof       uint16 = 24 // NSEC3 proof does not cover name
	EDECodeNSEC3ChainBroken        uint16 = 25 // NSEC3 hash chain is broken
	EDECodeNSEC3NoMatchingName     uint16 = 26 // NSEC3 owner name hash doesn't match
)

// String returns a human-readable description of the EDE code per RFC 8914.
func (e *EDE) String() string {
	switch e.Code {
	case EDECodeOther:
		return "other error"
	case EDECodeUnsupportedDNSKEYAlgo:
		return "unsupported-dnskey-algorithm"
	case EDECodeUnsupportedDSDigest:
		return "unsupported-ds-digest"
	case EDECodeStaleAnswer:
		return "stale-answer"
	case EDECodeForgedAnswer:
		return "forged-answer"
	case EDECodeIndeterminate:
		return "dnssec-indeterminate"
	case EDECodeBogus:
		return "dnssec-bogus"
	case EDECodeSignatureExpired:
		return "signature-expired"
	case EDECodeSignatureNotYetValid:
		return "signature-not-yet-valid"
	case EDECodeDNSKEYMissing:
		return "dnskey-missing"
	case EDECodeDSMissing:
		return "ds-missing"
	case EDECodeNoZoneKeyBitSet:
		return "no-zone-key-bit-set"
	case EDECodeSignatureUnsupported:
		return "signature-unsupported"
	case EDECodeDNSKEYNotAnchor:
		return "dnskey-not-anchor"
	case EDECodeTrustAnchorUnknown:
		return "trust-anchor-unknown"
	case EDECodeExpectedAnswerAfterDNL:
		return "expected-answer-after-dnl"
	case EDECodeDelegationNotServed:
		return "delegation-not-served"
	case EDECodeTTLMismatch:
		return "ttl-mismatch"
	case EDECodeCachedValidatedResponse:
		return "cached-validated-response"
	case EDECodeNSEC3HashAlgoUnsupported:
		return "nsec3-hash-algo-unsupported"
	case EDECodeNSEC3InvalidProof:
		return "nsec3-invalid-proof"
	case EDECodeNSEC3ChainBroken:
		return "nsec3-chain-broken"
	case EDECodeNSEC3NoMatchingName:
		return "nsec3-no-matching-name"
	default:
		return "unknown-error"
	}
}

// ValidationResult contains the result of DNSSEC validation.
type ValidationResult struct {
	Valid   bool
	ADBit   bool
	EDE     *EDE
}

// GetTrustAnchor returns the trust anchor (DNSKEY) for the given zone.
func (v *DNSSECValidator) GetTrustAnchor(zone string) *packet.DNSRecord {
	if anchor, ok := v.trustAnchors[zone]; ok {
		return &anchor
	}
	return nil
}

// ValidateRRSet validates an RRset with its RRSIGs and DNSKEYs.
// Returns whether the RRset is valid, the AD bit value, and an EDE if applicable.
func (v *DNSSECValidator) ValidateRRSet(rrset, rrsigs, dnskeys []packet.DNSRecord, now uint32) ValidationResult {
	if len(rrset) == 0 || len(rrsigs) == 0 || len(dnskeys) == 0 {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeBogus, Info: "missing required records"},
		}
	}

	// Find the RRSIG covering this RRset
	var rrsig *packet.DNSRecord
	for i := range rrsigs {
		if rrsigs[i].Type == packet.RRSIG && uint16(rrset[0].Type) == rrsigs[i].TypeCovered {
			rrsig = &rrsigs[i]
			break
		}
	}

	if rrsig == nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeBogus, Info: "no matching RRSIG found"},
		}
	}

	// Find the matching DNSKEY for this RRSIG
	dnskey := packet.FindMatchingDNSKEY(*rrsig, dnskeys)
	if dnskey == nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeDNSKEYMissing, Info: "dnskey-missing"},
		}
	}

	// Validate DNSKEY format
	if valid, err := packet.ValidateDNSKEYFormat(*dnskey); !valid || err != nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeBogus, Info: "invalid-dnskey-format"},
		}
	}

	// Verify the signature
	valid, err := packet.VerifyRRSet(rrset, *rrsig, *dnskey, now)
	if err != nil {
		switch {
		case errors.Is(err, packet.ErrSignatureExpired):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeSignatureExpired, Info: "signature-expired"},
			}
		case errors.Is(err, packet.ErrSignatureNotYetValid):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeSignatureNotYetValid, Info: "signature-not-yet-valid"},
			}
		case errors.Is(err, packet.ErrKeyTagMismatch):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeBogus, Info: "key-tag-mismatch"},
			}
		case errors.Is(err, packet.ErrAlgorithmMismatch):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeUnsupportedDNSKEYAlgo, Info: "algorithm-mismatch"},
			}
		case errors.Is(err, packet.ErrInvalidSignature):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeBogus, Info: "invalid-signature"},
			}
		default:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeOther, Info: err.Error()},
			}
		}
	}

	if !valid {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeBogus, Info: "signature verification failed"},
		}
	}

	return ValidationResult{
		Valid: true,
		ADBit: true,
	}
}

// ValidateDNSKEYChain validates the DNSSEC trust chain from DNSKEY to parent.
// It verifies that the DNSKEY matches the DS record.
func (v *DNSSECValidator) ValidateDNSKEYChain(dnskeys []packet.DNSRecord, ds, _ packet.DNSRecord) error {
	if len(dnskeys) == 0 {
		return fmt.Errorf("dnssec: no dnskeys provided")
	}

	// Find the DNSKEY that matches the DS record
	var matchedDNSKEY *packet.DNSRecord
	for i := range dnskeys {
		dnskey := &dnskeys[i]
		if dnskey.Type != packet.DNSKEY {
			continue
		}
		valid, err := packet.VerifyDNSKEYMatchesDS(*dnskey, ds)
		if err == nil && valid {
			matchedDNSKEY = dnskey
			break
		}
	}

	if matchedDNSKEY == nil {
		return fmt.Errorf("dnssec: no matching dnskey found for ds")
	}

	// Validate the matched DNSKEY format
	valid, err := packet.ValidateDNSKEYFormat(*matchedDNSKEY)
	if !valid || err != nil {
		return fmt.Errorf("dnssec: invalid dnskey format: %w", err)
	}

	return nil
}

// ChainLink represents a single step in the DNSSEC validation chain.
type ChainLink struct {
	Zone      string             // Zone name (e.g., "example.com.")
	DNSKEYs   []packet.DNSRecord // DNSKEYs for this zone
	DS        packet.DNSRecord   // DS record in parent (empty for trust anchor zone)
	RRSIGsDS  []packet.DNSRecord // RRSIG records signing the DS RRset
}

// ValidateChain validates the full DNSSEC trust chain from a leaf zone to a trust anchor.
// It verifies that each zone's DNSKEY is valid according to its DS record,
// and that DS records are properly signed up the chain to the trust anchor.
func (v *DNSSECValidator) ValidateChain(chain []ChainLink, now uint32) error {
	if len(chain) == 0 {
		return fmt.Errorf("dnssec: empty chain")
	}

	// Validate from leaf to root (last link should be trust anchor zone)
	for i := 0; i < len(chain); i++ {
		link := &chain[i]

		// Find matching DNSKEY for DS (if DS exists)
		if link.DS.Type != 0 {
			var matchedDNSKEY *packet.DNSRecord
			for j := range link.DNSKEYs {
				dnskey := &link.DNSKEYs[j]
				if dnskey.Type != packet.DNSKEY {
					continue
				}
				valid, err := packet.VerifyDNSKEYMatchesDS(*dnskey, link.DS)
				if err == nil && valid {
					matchedDNSKEY = dnskey
					break
				}
			}
			if matchedDNSKEY == nil {
				return fmt.Errorf("dnssec: chain link %d: no matching dnskey found for ds", i)
			}

			// Validate DNSKEY format
			if valid, err := packet.ValidateDNSKEYFormat(*matchedDNSKEY); !valid || err != nil {
				return fmt.Errorf("dnssec: chain link %d: invalid dnskey format: %w", i, err)
			}

			// Verify RRSIG_DS signatures using parent zone's DNSKEYs (chain[i+1].DNSKEYs)
			// The DS record for zone[i] is signed by the parent zone's ZSK
			if i+1 < len(chain) {
				parentLink := &chain[i+1]
				if len(link.RRSIGsDS) > 0 && len(parentLink.DNSKEYs) > 0 {
					// Find the RRSIG that covers DS (TypeCovered should be DS)
					var rrsig *packet.DNSRecord
					for idx := range link.RRSIGsDS {
						if link.RRSIGsDS[idx].Type == packet.RRSIG && link.RRSIGsDS[idx].TypeCovered == uint16(packet.DS) {
							rrsig = &link.RRSIGsDS[idx]
							break
						}
					}
					if rrsig == nil {
						return fmt.Errorf("dnssec: chain link %d: no RRSIG found for DS", i)
					}

					// Find matching DNSKEY in parent zone to verify the RRSIG
					parentDNSKEY := packet.FindMatchingDNSKEY(*rrsig, parentLink.DNSKEYs)
					if parentDNSKEY == nil {
						return fmt.Errorf("dnssec: chain link %d: no matching DNSKEY in parent zone for RRSIG_DS", i)
					}

					// Verify the RRSIG_DS signature
					valid, err := packet.VerifyRRSet([]packet.DNSRecord{link.DS}, *rrsig, *parentDNSKEY, now)
					if err != nil || !valid {
						return fmt.Errorf("dnssec: chain link %d: RRSIG_DS signature verification failed: %w", i, err)
					}
				}
			}
		}

		// If this link has a trust anchor, verify DNSKEY matches it
		if anchor := v.GetTrustAnchor(link.Zone); anchor != nil {
			var found bool
			for j := range link.DNSKEYs {
				dnskey := &link.DNSKEYs[j]
				if dnskey.Type == packet.DNSKEY &&
					dnskey.ComputeKeyTag() == anchor.ComputeKeyTag() &&
					dnskey.Algorithm == anchor.Algorithm {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("dnssec: chain link %d: dnskey does not match trust anchor for %s", i, link.Zone)
			}
		}
	}

	return nil
}

// ValidateWithTrustAnchor validates an RRset using trust anchors.
// It checks if any of the DNSKEYs is a trust anchor for the zone.
func (v *DNSSECValidator) ValidateWithTrustAnchor(zone string, rrset, rrsigs, dnskeys []packet.DNSRecord, now uint32) ValidationResult {
	anchor := v.GetTrustAnchor(zone)
	if anchor == nil {
		// No trust anchor - try regular validation
		return v.ValidateRRSet(rrset, rrsigs, dnskeys, now)
	}

	// Find if any DNSKEY matches the trust anchor
	var trustDNSKEY *packet.DNSRecord
	for i := range dnskeys {
		if dnskeys[i].Type == packet.DNSKEY {
			// Check if this DNSKEY matches the trust anchor
			if dnskeys[i].ComputeKeyTag() == anchor.ComputeKeyTag() &&
				dnskeys[i].Algorithm == anchor.Algorithm {
				trustDNSKEY = &dnskeys[i]
				break
			}
		}
	}

	if trustDNSKEY == nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeTrustAnchorUnknown, Info: "trust-anchor-not-found"},
		}
	}

	// Find RRSIG
	var rrsig *packet.DNSRecord
	for i := range rrsigs {
		if rrsigs[i].Type == packet.RRSIG && uint16(rrset[0].Type) == rrsigs[i].TypeCovered {
			rrsig = &rrsigs[i]
			break
		}
	}

	if rrsig == nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeBogus, Info: "no matching rrsig found"},
		}
	}

	// Verify using trust anchor DNSKEY
	valid, err := packet.VerifyRRSet(rrset, *rrsig, *trustDNSKEY, now)
	if err != nil {
		switch {
		case errors.Is(err, packet.ErrSignatureExpired):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeSignatureExpired, Info: "signature-expired"},
			}
		case errors.Is(err, packet.ErrSignatureNotYetValid):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeSignatureNotYetValid, Info: "signature-not-yet-valid"},
			}
		case errors.Is(err, packet.ErrKeyTagMismatch):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeBogus, Info: "key-tag-mismatch"},
			}
		case errors.Is(err, packet.ErrAlgorithmMismatch):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeUnsupportedDNSKEYAlgo, Info: "algorithm-mismatch"},
			}
		case errors.Is(err, packet.ErrInvalidSignature):
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeBogus, Info: "invalid-signature"},
			}
		default:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: EDECodeOther, Info: err.Error()},
			}
		}
	}

	if !valid {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: EDECodeBogus, Info: "trust-anchor validation failed"},
		}
	}

	return ValidationResult{
		Valid: true,
		ADBit: true,
	}
}
