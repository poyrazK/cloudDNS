package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/core/utils"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

// generateServerCookie generates a server cookie as defined in RFC 9013.
func (s *Server) generateServerCookie(clientCookie []byte, clientIP string) []byte {
	h := hmac.New(sha256.New, s.CookieSecret)
	h.Write(clientCookie)
	h.Write([]byte(clientIP))
	return h.Sum(nil)[:16] // Return 16 bytes of server cookie
}

// padResponse pads a DNS response to a multiple of blockSize for privacy (RFC 9276).
func (s *Server) padResponse(response *packet.DNSPacket, blockSize int) {
	// Find OPT record
	var opt *packet.DNSRecord
	for i := range response.Resources {
		if response.Resources[i].Type == packet.OPT {
			opt = &response.Resources[i]
			break
		}
	}

	if opt == nil {
		// PADDING requires an OPT record.
		return
	}

	// Remove existing padding if any to avoid double padding
	for i, o := range opt.Options {
		if o.Code == packet.EdnsOptionPadding {
			opt.Options = append(opt.Options[:i], opt.Options[i+1:]...)
			break
		}
	}

	// Calculate current size with compression enabled
	buf := packet.GetBuffer()
	defer packet.PutBuffer(buf)
	buf.HasNames = true
	_ = response.Write(buf)
	currentSize := buf.Position()

	// The Padding option itself adds 4 bytes (code + length)
	overhead := 4
	needed := blockSize - (currentSize+overhead)%blockSize
	if (currentSize+overhead)%blockSize == 0 {
		needed = 0
	}

	padding := make([]byte, needed)
	opt.SetOption(packet.EdnsOptionPadding, padding)
}

// automateDNSSEC runs periodic DNSSEC key lifecycle management for all zones.
func (s *Server) automateDNSSEC() {
	ctx := s.lifecycleCtx
	// Get all zones
	zones, errList := s.Repo.ListZones(ctx, "")
	if errList != nil {
		return
	}

	for _, z := range zones {
		if errAutomate := s.DNSSEC.AutomateLifecycle(ctx, z.ID); errAutomate != nil {
			s.Logger.Error("DNSSEC automation failed for zone", "zone", z.Name, "error", errAutomate)
		}
	}

	// Update DNSSEC key metrics after automation
	s.updateDNSSECMetrics(ctx)
}

// updateDNSSECMetrics collects and reports DNSSEC key statistics.
func (s *Server) updateDNSSECMetrics(ctx context.Context) {
	if s.DNSSEC == nil {
		return
	}
	stats, err := s.DNSSEC.CollectKeyStats(ctx)
	if err != nil {
		s.Logger.Debug("failed to collect DNSSEC key stats", "error", err)
		return
	}
	metrics.DNSSECKeysTotal.Reset()
	metrics.DNSSECKeysAgeSeconds.Reset()
	signedZones := 0
	for _, st := range stats {
		metrics.DNSSECKeysTotal.WithLabelValues(st.ZoneName, st.KeyType, fmt.Sprintf("%d", st.Algorithm)).Set(1)
		metrics.DNSSECKeysAgeSeconds.WithLabelValues(st.ZoneName, st.KeyType).Set(st.AgeSeconds)
		signedZones++
	}
	metrics.DNSSECZonesSigned.Set(float64(signedZones))
}

// signResponse signs a DNS response with the zone's DNSSEC keys.
func (s *Server) signResponse(ctx context.Context, zone *domain.Zone, response *packet.DNSPacket) {
	// Sign Answers
	if len(response.Answers) > 0 {
		groups := s.groupRecords(response.Answers)
		for _, group := range groups {
			sigs, errSign := s.DNSSEC.SignRRSet(ctx, zone.Name, zone.ID, group)
			if errSign == nil {
				response.Answers = append(response.Answers, sigs...)
			}
		}
	}
	// Sign Authorities
	if len(response.Authorities) > 0 {
		groups := s.groupRecords(response.Authorities)
		for _, group := range groups {
			sigs, errSign := s.DNSSEC.SignRRSet(ctx, zone.Name, zone.ID, group)
			if errSign == nil {
				response.Authorities = append(response.Authorities, sigs...)
			}
		}
	}
}

// validateDNSSEC validates DNSSEC signatures on a response.
// It checks the AD bit based on validation result and dnssecMode.
// Returns an error if validation failed (in strict mode) or if DNSKEYs could not be fetched.
func (s *Server) validateDNSSEC(ctx context.Context, zoneName string, response *packet.DNSPacket) error {
	if s.DNSSECValidator == nil || s.DNSSECMode == "disabled" {
		return nil
	}

	// Collect all RRSIGs from the response, grouped by covered rrset
	// Key: "name:typeCovered" -> value: []packet.DNSRecord of RRSIGs
	rrsigGroups := make(map[string][]packet.DNSRecord)
	for _, rec := range response.Answers {
		if rec.Type == packet.RRSIG {
			lowerName := strings.ToLower(rec.Name)
			key := lowerName + ":" + fmt.Sprintf("%d", rec.TypeCovered)
			rrsigGroups[key] = append(rrsigGroups[key], rec)
		}
	}
	for _, rec := range response.Authorities {
		if rec.Type == packet.RRSIG {
			lowerName := strings.ToLower(rec.Name)
			key := lowerName + ":" + fmt.Sprintf("%d", rec.TypeCovered)
			rrsigGroups[key] = append(rrsigGroups[key], rec)
		}
	}

	if len(rrsigGroups) == 0 {
		return nil // No signatures to validate
	}

	// Fetch DNSKEYs for validation
	dnskeyRecords, err := s.Repo.GetDNSKEYs(ctx, zoneName)
	if err != nil {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: failed to fetch dnskeys: %w", err)
		}
		return nil
	}

	// If no DNSKEYs from repo, try fetching from network
	if len(dnskeyRecords) == 0 && s.RecursionEnabled {
		netDNSKEYs, netErr := s.fetchDNSKEYFromNetwork(ctx, zoneName)
		if netErr == nil {
			// Convert network DNSKEYs to domain records
			for _, dk := range netDNSKEYs {
				if domRec, err := repository.ConvertPacketRecordToDomain(dk, ""); err == nil {
					dnskeyRecords = append(dnskeyRecords, domRec)
				}
			}
		}
	}

	if len(dnskeyRecords) == 0 {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: no dnskeys available for validation")
		}
		return nil
	}

	// Convert domain records to packet records for validation
	var dnskeys []packet.DNSRecord
	for _, rec := range dnskeyRecords {
		pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
		if errConv != nil {
			continue
		}
		if pRec.Type != packet.DNSKEY {
			continue
		}
		if pRec.Type == packet.DNSKEY && len(pRec.PublicKey) > 0 {
			dnskeys = append(dnskeys, pRec)
		}
	}

	if len(dnskeys) == 0 {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: no valid dnskeys found")
		}
		return nil
	}

	// Get current time for validation.
	now := utils.GetCurrentTimeUint32()

	// Validate each unique RRset with its matching RRSIGs
	allValid := true
	for key, sigs := range rrsigGroups {
		// Parse key to get name and type
		parts := strings.Split(key, ":")
		if len(parts) != 2 {
			continue
		}
		rrsigName := parts[0]
		coveredType := packet.QueryType(0)
		if _, err := fmt.Sscanf(parts[1], "%d", &coveredType); err != nil {
			continue
		}

		// Build the RRset from response.Answers and response.Authorities
		var rrset []packet.DNSRecord
		for _, ans := range response.Answers {
			if ans.Type == coveredType && strings.ToLower(ans.Name) == rrsigName {
				rrset = append(rrset, ans)
			}
		}
		for _, auth := range response.Authorities {
			if auth.Type == coveredType && strings.ToLower(auth.Name) == rrsigName {
				rrset = append(rrset, auth)
			}
		}

		if len(rrset) == 0 {
			continue // No matching rrset for this group of RRSIGs
		}

		result := s.DNSSECValidator.ValidateRRSet(rrset, sigs, dnskeys, now)
		if !result.Valid {
			allValid = false
			if s.DNSSECMode == "strict" {
				return fmt.Errorf("dnssec: validation failed for %s: %v", rrsigName, result.EDE)
			}
		}
	}

	// Build and validate the trust chain from leaf to trust anchor
	chain, chainErr := s.buildDNSSECChain(ctx, zoneName)
	if chainErr != nil {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: failed to build trust chain: %w", chainErr)
		}
		// Non-strict: fall through to RRset result below
	} else if validateErr := s.DNSSECValidator.ValidateChain(chain, now); validateErr != nil {
		if s.DNSSECMode == "strict" {
			return fmt.Errorf("dnssec: trust chain validation failed: %w", validateErr)
		}
		// Chain invalid in non-strict mode — AD bit must be false, not allValid
		response.Header.AuthedData = false
		return nil
	} else {
		// Chain valid — but AD requires both chain AND per-RRset validation to succeed
		if s.DNSSECMode == "strict" && !allValid {
			return fmt.Errorf("dnssec: chain valid but per-RRset validation failed")
		}
		response.Header.AuthedData = allValid
		return nil
	}

	response.Header.AuthedData = allValid
	return nil
}

// fetchDNSKEYFromNetwork queries DNSKEY records for a zone from the network.
func (s *Server) fetchDNSKEYFromNetwork(ctx context.Context, zoneName string) ([]packet.DNSRecord, error) {
	// First try to resolve DNSKEY via recursive resolution
	dnskeyResp, err := s.resolveRecursive(ctx, zoneName, packet.DNSKEY)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNSKEY for %s: %w", zoneName, err)
	}

	var dnskeys []packet.DNSRecord
	// Collect DNSKEY records from answers
	for _, rec := range dnskeyResp.Answers {
		if rec.Type == packet.DNSKEY && len(rec.PublicKey) > 0 {
			dnskeys = append(dnskeys, rec)
		}
	}
	// Also check authorities (some servers put DNSKEYs there)
	for _, rec := range dnskeyResp.Authorities {
		if rec.Type == packet.DNSKEY && len(rec.PublicKey) > 0 {
			dnskeys = append(dnskeys, rec)
		}
	}

	if len(dnskeys) == 0 {
		return nil, fmt.Errorf("no DNSKEY records found for %s", zoneName)
	}
	return dnskeys, nil
}

// fetchDSFromNetwork queries DS records for a child zone from the parent zone.
func (s *Server) fetchDSFromNetwork(ctx context.Context, childZone, parentZone string) ([]packet.DNSRecord, []packet.DNSRecord, error) {
	// Query for the child zone's DS record (from the parent zone's authority)
	dsResp, err := s.resolveRecursive(ctx, childZone, packet.DS)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve DS for %s from %s: %w", childZone, parentZone, err)
	}

	var dsRecords []packet.DNSRecord
	var rrsigDSRecords []packet.DNSRecord

	// Collect DS records matching the child zone
	for _, rec := range dsResp.Answers {
		if rec.Type == packet.DS && strings.EqualFold(rec.Name, childZone) {
			dsRecords = append(dsRecords, rec)
		}
		if rec.Type == packet.RRSIG && rec.TypeCovered == uint16(packet.DS) {
			rrsigDSRecords = append(rrsigDSRecords, rec)
		}
	}

	// RRSIG_DS may also be in authorities section
	for _, rec := range dsResp.Authorities {
		if rec.Type == packet.RRSIG && rec.TypeCovered == uint16(packet.DS) {
			rrsigDSRecords = append(rrsigDSRecords, rec)
		}
	}

	return dsRecords, rrsigDSRecords, nil
}

// buildDNSSECChain builds a trust chain from leaf zone to trust anchor.
func (s *Server) buildDNSSECChain(ctx context.Context, zoneName string) ([]services.ChainLink, error) {
	if s.DNSSECValidator == nil {
		return nil, fmt.Errorf("dnssec: no validator configured")
	}

	var chain []services.ChainLink
	currentZone := zoneName

	// Max depth to prevent infinite loops (root + 2-3 levels of typical delegation)
	const maxDepth = 10

	for len(chain) < maxDepth {
		// Fetch DNSKEYs for current zone
		dnskeyRecs, err := s.fetchDNSKEYFromNetwork(ctx, currentZone)
		if err != nil {
			return nil, fmt.Errorf("buildDNSSECChain: failed to fetch DNSKEYs for %s: %w", currentZone, err)
		}

		link := services.ChainLink{
			Zone:    currentZone,
			DNSKEYs: dnskeyRecs,
		}

		// If we have a parent, fetch DS + RRSIG_DS from parent
		parentZone := parentZoneName(currentZone)
		if parentZone != "" && parentZone != "." {
			dsRecs, rrsigDSRecs, dsErr := s.fetchDSFromNetwork(ctx, currentZone, parentZone)
			if dsErr != nil {
				return nil, fmt.Errorf("buildDNSSECChain: failed to fetch DS for %s from %s: %w", currentZone, parentZone, dsErr)
			}
			// Take the first DS record (zones typically have one DS per signing key)
			if len(dsRecs) > 0 {
				link.DS = dsRecs[0]
			}
			link.RRSIGsDS = rrsigDSRecs
		}

		chain = append(chain, link)

		// Check if current zone is a trust anchor
		if s.DNSSECValidator.GetTrustAnchor(currentZone) != nil {
			break
		}

		// Move to parent zone
		if parentZone == "" || parentZone == "." {
			break
		}
		currentZone = parentZone
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("buildDNSSECChain: could not build chain for %s", zoneName)
	}

	// Verify we reached a trust anchor
	if s.DNSSECValidator.GetTrustAnchor(chain[len(chain)-1].Zone) == nil {
		return nil, fmt.Errorf("buildDNSSECChain: could not verify chain to trust anchor for %s", zoneName)
	}

	return chain, nil
}

// groupRecords groups DNS records by name and type for response assembly.
func (s *Server) groupRecords(records []packet.DNSRecord) [][]packet.DNSRecord {
	groups := make(map[string][]packet.DNSRecord)
	var keys []string
	for _, r := range records {
		if r.Type == packet.RRSIG || r.Type == packet.OPT || r.Type == packet.TSIG {
			continue
		}
		lowerName := strings.ToLower(r.Name)
		key := lowerName + ":" + fmt.Sprintf("%d", r.Type)
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], r)
	}

	res := make([][]packet.DNSRecord, 0, len(keys))
	for _, k := range keys {
		res = append(res, groups[k])
	}
	return res
}