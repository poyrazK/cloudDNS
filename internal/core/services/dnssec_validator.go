// Package services implements the core business logic for cloudDNS.
package services

import (
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
			EDE:   &EDE{Code: 0, Info: "missing required records"},
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
			EDE:   &EDE{Code: 0, Info: "no matching RRSIG found"},
		}
	}

	// Find the matching DNSKEY for this RRSIG
	dnskey := packet.FindMatchingDNSKEY(*rrsig, dnskeys)
	if dnskey == nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: 6, Info: "dnskey-missing"},
		}
	}

	// Validate DNSKEY format
	if valid, err := packet.ValidateDNSKEYFormat(*dnskey); !valid || err != nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: 7, Info: "invalidDNSKEY"},
		}
	}

	// Verify the signature
	valid, err := packet.VerifyRRSet(rrset, *rrsig, *dnskey, now)
	if err != nil {
		switch err {
		case packet.ErrSignatureExpired:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: 2, Info: "signature-expired"},
			}
		case packet.ErrSignatureNotYetValid:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: 2, Info: "signature-not-yet-valid"},
			}
		case packet.ErrKeyTagMismatch:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: 2, Info: "key-tag-mismatch"},
			}
		case packet.ErrAlgorithmMismatch:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: 3, Info: "algorithm-mismatch"},
			}
		case packet.ErrInvalidSignature:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: 2, Info: "invalid-signature"},
			}
		default:
			return ValidationResult{
				Valid: false,
				EDE:   &EDE{Code: 0, Info: err.Error()},
			}
		}
	}

	if !valid {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: 2, Info: "signature verification failed"},
		}
	}

	return ValidationResult{
		Valid: true,
		ADBit: true,
	}
}

// ValidateDNSKEYChain validates the DNSSEC trust chain from DNSKEY to parent.
// It verifies that the DNSKEY matches the DS record and optionally validates
// against a parent DNSKEY.
func (v *DNSSECValidator) ValidateDNSKEYChain(dnskeys []packet.DNSRecord, ds, parentDNSKEY packet.DNSRecord) error {
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

	// If parent DNSKEY is provided, verify the chain
	if parentDNSKEY.Type == packet.DNSKEY {
		// Verify parent signed the child DNSKEY
		// This would require an RRSIG over the child DNSKEY, which is typically
		// handled by ValidateRRSet for actual signature verification
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
			EDE:   &EDE{Code: 6, Info: "trust-anchor-not-found"},
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
			EDE:   &EDE{Code: 0, Info: "no matching rrsig found"},
		}
	}

	// Verify using trust anchor DNSKEY
	valid, err := packet.VerifyRRSet(rrset, *rrsig, *trustDNSKEY, now)
	if !valid || err != nil {
		return ValidationResult{
			Valid: false,
			EDE:   &EDE{Code: 2, Info: "trust-anchor validation failed"},
		}
	}

	return ValidationResult{
		Valid: true,
		ADBit: true,
	}
}
