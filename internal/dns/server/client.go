package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// refreshZone initiates a zone refresh for a slave zone by querying the master for SOA.
func (s *Server) refreshZone(ctx context.Context, zone *domain.Zone) {
	if zone.MasterServer == "" {
		s.Logger.Warn("slave zone has no master server configured", "zone", zone.Name)
		return
	}

	masterAddr := zone.MasterServer
	if _, _, err := net.SplitHostPort(masterAddr); err != nil {
		// No port found (or malformed), default to 53
		masterAddr = net.JoinHostPort(masterAddr, "53")
	}
	s.Logger.Info("initiating zone refresh", "zone", zone.Name, "master", masterAddr)

	// 1. Query master for SOA
	masterPacket, err := s.queryFn(masterAddr, zone.Name, packet.SOA)
	if err != nil {
		s.Logger.Error("failed to query master SOA", "zone", zone.Name, "error", err)
		return
	}

	if len(masterPacket.Answers) == 0 || masterPacket.Answers[0].Type != packet.SOA {
		s.Logger.Warn("master returned no SOA for zone", "zone", zone.Name)
		return
	}

	masterSOA := masterPacket.Answers[0]

	// 2. Get local SOA
	records, err := s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, "")
	if err != nil {
		s.Logger.Error("failed to get local records for refresh", "zone", zone.Name, "error", err)
		return
	}

	var localSerial uint32
	if len(records) > 0 {
		// Parse serial from SOA content
		parts := strings.Fields(records[0].Content)
		if len(parts) >= 3 {
			if _, err := fmt.Sscanf(parts[2], "%d", &localSerial); err != nil {
				s.Logger.Warn("failed to parse local SOA serial", "content", records[0].Content, "error", err)
			}
		}
	}

	s.Logger.Info("comparing serials", "zone", zone.Name, "local", localSerial, "master", masterSOA.Serial)

	if localSerial >= masterSOA.Serial && localSerial != 0 {
		s.Logger.Info("zone is up to date", "zone", zone.Name)
		return
	}

	// 3. Initiate transfer: Try IXFR first, then fall back to AXFR
	if localSerial != 0 {
		s.Logger.Info("attempting IXFR", "zone", zone.Name, "from", localSerial)
		if err := s.performIXFR(ctx, zone, masterAddr, localSerial); err == nil {
			s.Logger.Info("IXFR successful", "zone", zone.Name)
			return
		}
		s.Logger.Warn("IXFR failed, falling back to AXFR", "zone", zone.Name, "error", err)
	}

	if err := s.performAXFR(ctx, zone, masterAddr); err != nil {
		s.Logger.Error("AXFR failed", "zone", zone.Name, "error", err)
	}
}

// performIXFR performs an incremental zone transfer from the master server.
func (s *Server) performIXFR(ctx context.Context, zone *domain.Zone, masterAddr string, localSerial uint32) error {
	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Construct IXFR query
	req := packet.NewDNSPacket()
	req.Header.ID = generateTransactionID()
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:   zone.Name,
		QType:  packet.IXFR,
		QClass: 1,
	})

	// Add client's current SOA to Authority section
	localSOARecords, err := s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, "")
	if err != nil {
		return fmt.Errorf("failed to fetch local SOA for IXFR: %w", err)
	}
	if len(localSOARecords) > 0 {
		pSOA, errConv := repository.ConvertDomainToPacketRecord(localSOARecords[0])
		if errConv != nil {
			return fmt.Errorf("failed to convert local SOA for IXFR: %w", errConv)
		}
		req.Authorities = append(req.Authorities, pSOA)
	} else {
		return fmt.Errorf("local SOA not found for zone %s", zone.Name)
	}

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return err
	}
	data := buffer.Buf[:buffer.Position()]
	prefix := []byte{byte((len(data) >> 8) & 0xFF), byte(len(data) & 0xFF)}
	if _, err := conn.Write(append(prefix, data...)); err != nil {
		return err
	}

	// State machine for IXFR
	var allRecords []packet.DNSRecord
	first := true
	isIncremental := false
	soaCount := 0
	var masterSerial uint32

	for {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		pLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		pData := make([]byte, pLen)
		if _, err := io.ReadFull(conn, pData); err != nil {
			return err
		}

		resBuffer := packet.NewBytePacketBuffer()
		resBuffer.Load(pData)
		resp := packet.NewDNSPacket()
		if err := resp.FromBuffer(resBuffer); err != nil {
			return err
		}

		if resp.Header.ResCode != packet.RcodeNoError {
			return fmt.Errorf("master returned error: %d", resp.Header.ResCode)
		}

		done := false
		for _, ans := range resp.Answers {
			if first {
				if ans.Type != packet.SOA {
					return fmt.Errorf("first record must be SOA")
				}
				masterSerial = ans.Serial
				if ans.Serial <= localSerial {
					return nil // Already up to date
				}
				first = false
				// Initial Current SOA skipped for counting/allRecords
				continue
			}

			if ans.Type == packet.SOA {
				soaCount++
				if soaCount == 1 {
					// RFC 1995: The first record after the initial SOA MUST be the
					// version the client requested (localSerial) for it to be incremental.
					// If it's anything else (like masterSerial again), it's AXFR fallback.
					isIncremental = ans.Serial == localSerial
				}

				// Termination check:
				// Incremental: ODD SOA count (>1) matching master serial marks end
				if isIncremental && soaCount > 1 && soaCount%2 == 1 && ans.Serial == masterSerial {
					done = true
					break
				}
				// AXFR Fallback check: second SOA (soaCount == 1 since we skip first) marks end
				if !isIncremental && soaCount == 1 {
					done = true
					// Don't break yet, we might want to include this SOA if it's AXFR
				}
			}
			allRecords = append(allRecords, ans)
			if done {
				break
			}
		}
		if done {
			break
		}
	}

	if !isIncremental {
		// AXFR Fallback
		var newRecords []domain.Record
		for _, r := range allRecords {
			dRec, errConv := repository.ConvertPacketRecordToDomain(r, zone.ID)
			if errConv != nil {
				s.Logger.Warn("failed to convert packet record in AXFR fallback", "error", errConv)
				continue
			}
			dRec.TenantID = zone.TenantID
			newRecords = append(newRecords, dRec)
		}
		if err := s.Repo.DeleteRecordsForZone(ctx, zone.ID); err != nil {
			return fmt.Errorf("AXFR fallback failed to clear zone: %w", err)
		}
		if err := s.Repo.BatchCreateRecords(ctx, newRecords); err != nil {
			return err // BatchCreateRecords already wraps errors, don't double-wrap
		}
		return nil
	}

	// Incremental logic: Apply Deletions then Additions
	// The sequence is [SOA(old), deleted..., SOA(new), added...]
	deleting := false
	for _, r := range allRecords {
		dRec, errConv := repository.ConvertPacketRecordToDomain(r, zone.ID)
		if errConv != nil {
			s.Logger.Warn("failed to convert record in IXFR delta", "error", errConv)
			return errConv
		}
		if r.Type == packet.SOA {
			deleting = !deleting
			if !deleting {
				// This is SOA(new), save it to update local serial
				dRec.TenantID = zone.TenantID
				if err := s.Repo.CreateRecord(ctx, &dRec); err != nil {
					return fmt.Errorf("IXFR failed to save new SOA: %w", err)
				}
			} else {
				// This is SOA(old), delete it
				if err := s.Repo.DeleteRecordSpecific(ctx, zone.ID, dRec.Name, dRec.Type, dRec.Content); err != nil {
					return fmt.Errorf("IXFR failed to delete old SOA: %w", err)
				}
			}
			continue
		}
		if deleting {
			if err := s.Repo.DeleteRecordSpecific(ctx, zone.ID, dRec.Name, dRec.Type, dRec.Content); err != nil {
				return fmt.Errorf("IXFR failed to delete record: %w", err)
			}
		} else {
			dRec.TenantID = zone.TenantID
			if err := s.Repo.CreateRecord(ctx, &dRec); err != nil {
				return fmt.Errorf("IXFR failed to create record: %w", err)
			}
		}
	}

	return nil
}

// performAXFR performs a full zone transfer from the master server.
func (s *Server) performAXFR(ctx context.Context, zone *domain.Zone, masterAddr string) error {
	s.Logger.Info("starting AXFR", "zone", zone.Name, "master", masterAddr)

	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			s.Logger.Warn("failed to close AXFR connection", "error", errClose)
		}
	}()

	// Construct AXFR query
	req := packet.NewDNSPacket()
	req.Header.ID = generateTransactionID()
	req.Header.RecursionDesired = false
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:   zone.Name,
		QType:  packet.AXFR,
		QClass: 1,
	})

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return err
	}

	// Write length-prefixed query
	data := buffer.Buf[:buffer.Position()]
	prefix := []byte{byte((len(data) >> 8) & 0xFF), byte(len(data) & 0xFF)}
	if _, err := conn.Write(append(prefix, data...)); err != nil {
		return err
	}

	var newRecords []domain.Record
	soaCount := 0

	for {
		// Read 2-byte length
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		pLen := int(lenBuf[0])<<8 | int(lenBuf[1])

		// Read packet
		pData := make([]byte, pLen)
		if _, err := io.ReadFull(conn, pData); err != nil {
			return err
		}

		resBuffer := packet.NewBytePacketBuffer()
		resBuffer.Load(pData)

		resp := packet.NewDNSPacket()
		if err := resp.FromBuffer(resBuffer); err != nil {
			return err
		}

		if resp.Header.ResCode != packet.RcodeNoError {
			return fmt.Errorf("master returned error: %d", resp.Header.ResCode)
		}

		for _, ans := range resp.Answers {
			if ans.Type == packet.SOA {
				soaCount++
			}
			
			dRec, err := repository.ConvertPacketRecordToDomain(ans, zone.ID)
			if err != nil {
				s.Logger.Warn("failed to convert packet record", "error", err)
				continue
			}
			dRec.TenantID = zone.TenantID
			newRecords = append(newRecords, dRec)
		}

		// AXFR ends when the second SOA is received
		if soaCount >= 2 {
			break
		}
	}

	s.Logger.Info("AXFR received all records, updating repository", "zone", zone.Name, "count", len(newRecords))

	// Atomic-ish update: delete all and batch create
	if err := s.Repo.DeleteRecordsForZone(ctx, zone.ID); err != nil {
		return fmt.Errorf("failed to clear old records: %w", err)
	}

	return s.Repo.BatchCreateRecords(ctx, newRecords)
}

// StartCatalogPoller starts a background goroutine that periodically polls
// catalog zones for changes and syncs zones to local storage.
func (s *Server) StartCatalogPoller(ctx context.Context, catalogZones []string, masterAddr string, pollInterval time.Duration) {
	if len(catalogZones) == 0 {
		s.Logger.Info("no catalog zones configured for polling")
		return
	}

	s.Logger.Info("starting catalog zone poller", "zones", catalogZones, "master", masterAddr, "interval", pollInterval)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Poll immediately on startup
	for _, catalogZoneName := range catalogZones {
		if err := s.pollCatalogZone(ctx, catalogZoneName, masterAddr); err != nil {
			s.Logger.Error("failed to poll catalog zone", "zone", catalogZoneName, "error", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			s.Logger.Info("catalog poller shutting down")
			return
		case <-ticker.C:
			for _, catalogZoneName := range catalogZones {
				if err := s.pollCatalogZone(ctx, catalogZoneName, masterAddr); err != nil {
					s.Logger.Error("failed to poll catalog zone", "zone", catalogZoneName, "error", err)
				}
			}
		}
	}
}

// pollCatalogZone polls a single catalog zone and syncs any new or changed zones.
func (s *Server) pollCatalogZone(ctx context.Context, catalogZoneName string, masterAddr string) error {
	s.Logger.Debug("polling catalog zone", "zone", catalogZoneName, "master", masterAddr)

	// Query CZTR to check if master supports catalog zone transfers
	cztrPacket, err := s.queryFn(masterAddr, catalogZoneName, packet.CZTR)
	if err != nil {
		s.Logger.Debug("master does not support CZTR, skipping catalog poll", "zone", catalogZoneName)
		return nil
	}

	if len(cztrPacket.Answers) == 0 {
		s.Logger.Debug("master returned empty CZTR, slave mode not supported", "zone", catalogZoneName)
		return nil
	}

	// Query SOA to get current serial for change detection
	soaPacket, err := s.queryFn(masterAddr, catalogZoneName, packet.SOA)
	if err != nil {
		s.Logger.Debug("failed to query catalog SOA", "zone", catalogZoneName, "error", err)
		// Continue anyway - AXFR will get the full contents
	} else if len(soaPacket.Answers) > 0 && soaPacket.Answers[0].Type == packet.SOA {
		currentSerial := soaPacket.Answers[0].Serial

		// Check if serial changed since last poll
		s.catalogState.mu.RLock()
		lastSerial, seen := s.catalogState.lastSeenSerial[catalogZoneName]
		s.catalogState.mu.RUnlock()

		if seen && lastSerial == currentSerial {
			s.Logger.Debug("catalog zone unchanged, skipping", "zone", catalogZoneName, "serial", currentSerial)
			return nil
		}

		// Update last seen serial
		s.catalogState.mu.Lock()
		s.catalogState.lastSeenSerial[catalogZoneName] = currentSerial
		s.catalogState.mu.Unlock()
	}

	// Fetch catalog entries via AXFR
	entries, err := s.fetchCatalogEntries(ctx, catalogZoneName, masterAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch catalog entries: %w", err)
	}

	s.Logger.Info("received catalog zone entries", "zone", catalogZoneName, "count", len(entries))

	// Sync each zone from catalog
	for _, entry := range entries {
		if err := s.syncZoneFromCatalog(ctx, &entry, masterAddr, s.NodeID); err != nil {
			s.Logger.Error("failed to sync zone from catalog", "zone", entry.ZoneName, "error", err)
		}
	}

	return nil
}

// fetchCatalogEntries performs AXFR on the catalog zone and extracts zone entries.
func (s *Server) fetchCatalogEntries(ctx context.Context, catalogZoneName string, masterAddr string) ([]domain.ZoneCatalogEntry, error) {
	if _, _, err := net.SplitHostPort(masterAddr); err != nil {
		masterAddr = net.JoinHostPort(masterAddr, "53")
	}

	s.Logger.Debug("performing AXFR for catalog zone", "zone", catalogZoneName, "master", masterAddr)

	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to master: %w", err)
	}
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			s.Logger.Warn("failed to close AXFR connection", "error", errClose)
		}
	}()

	// Construct AXFR query
	req := packet.NewDNSPacket()
	req.Header.ID = generateTransactionID()
	req.Header.RecursionDesired = false
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:   catalogZoneName,
		QType:  packet.AXFR,
		QClass: 1,
	})

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return nil, err
	}

	// Write length-prefixed query
	data := buffer.Buf[:buffer.Position()]
	prefix := []byte{byte((len(data) >> 8) & 0xFF), byte(len(data) & 0xFF)}
	if _, err := conn.Write(append(prefix, data...)); err != nil {
		return nil, err
	}

	var entries []domain.ZoneCatalogEntry
	soaCount := 0

	for {
		// Read 2-byte length
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		pLen := int(lenBuf[0])<<8 | int(lenBuf[1])

		// Read packet
		pData := make([]byte, pLen)
		if _, err := io.ReadFull(conn, pData); err != nil {
			return nil, err
		}

		resBuffer := packet.NewBytePacketBuffer()
		resBuffer.Load(pData)

		resp := packet.NewDNSPacket()
		if err := resp.FromBuffer(resBuffer); err != nil {
			return nil, err
		}

		if resp.Header.ResCode != packet.RcodeNoError {
			return nil, fmt.Errorf("master returned error: %d", resp.Header.ResCode)
		}

		for _, ans := range resp.Answers {
			if ans.Type == packet.SOA {
				soaCount++
			}

			// Extract zone entries from PTR records
			// Per RFC 9432, zones are stored as PTR records in the catalog zone
			if ans.Type == packet.PTR {
				// Content format: "zone_name:zone_id[:group_id]"
				parts := strings.SplitN(ans.Host, ":", 3)
				if len(parts) >= 2 {
					entry := domain.ZoneCatalogEntry{
						ZoneName: parts[0],
						ZoneID:   parts[1],
					}
					if len(parts) == 3 {
						entry.GroupID = parts[2]
					}
					entries = append(entries, entry)
					s.Logger.Debug("found catalog entry", "zone", entry.ZoneName, "id", entry.ZoneID)
				}
			}
		}

		// AXFR ends when the second SOA is received
		if soaCount >= 2 {
			break
		}
	}

	return entries, nil
}

// syncZoneFromCatalog provisions a single zone from a catalog entry.
func (s *Server) syncZoneFromCatalog(ctx context.Context, entry *domain.ZoneCatalogEntry, masterAddr string, tenantID string) error {
	// 1. Check if zone already exists by catalog zone name
	zones, err := s.Repo.ListZones(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to list zones: %w", err)
	}
	for _, z := range zones {
		if z.CatalogZoneName != nil && *z.CatalogZoneName == entry.ZoneName {
			s.Logger.Debug("zone already exists from catalog", "zone", entry.ZoneName)
			return nil
		}
	}

	// 2. Create zone record with catalog metadata
	zone := &domain.Zone{
		ID:              entry.ZoneID,
		TenantID:        tenantID,
		Name:            entry.ZoneName,
		Role:            "slave",
		MasterServer:    masterAddr,
		CatalogZoneName: &entry.ZoneName,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := s.Repo.CreateZone(ctx, zone); err != nil {
		return fmt.Errorf("failed to create zone: %w", err)
	}

	// 3. AXFR zone data from master
	records, err := s.fetchZoneRecords(ctx, entry.ZoneName, masterAddr, entry.ZoneID)
	if err != nil {
		s.Logger.Warn("failed to fetch zone records via AXFR, zone created without records", "zone", entry.ZoneName, "error", err)
		return nil
	}

	// 4. Batch create records
	if len(records) > 0 {
		if err := s.Repo.BatchCreateRecords(ctx, records); err != nil {
			return fmt.Errorf("failed to create zone records: %w", err)
		}
	}

	s.Logger.Info("provisioned zone from catalog", "zone", entry.ZoneName, "records", len(records))
	return nil
}

// fetchZoneRecords performs AXFR on a regular zone and returns the records.
func (s *Server) fetchZoneRecords(ctx context.Context, zoneName string, masterAddr string, zoneID string) ([]domain.Record, error) {
	if _, _, err := net.SplitHostPort(masterAddr); err != nil {
		masterAddr = net.JoinHostPort(masterAddr, "53")
	}

	s.Logger.Debug("performing AXFR for zone", "zone", zoneName, "master", masterAddr)

	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to master: %w", err)
	}
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			s.Logger.Warn("failed to close AXFR connection", "error", errClose)
		}
	}()

	// Construct AXFR query
	req := packet.NewDNSPacket()
	req.Header.ID = generateTransactionID()
	req.Header.RecursionDesired = false
	req.Questions = append(req.Questions, packet.DNSQuestion{
		Name:   zoneName,
		QType:  packet.AXFR,
		QClass: 1,
	})

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return nil, err
	}

	// Write length-prefixed query
	data := buffer.Buf[:buffer.Position()]
	prefix := []byte{byte((len(data) >> 8) & 0xFF), byte(len(data) & 0xFF)}
	if _, err := conn.Write(append(prefix, data...)); err != nil {
		return nil, err
	}

	var records []domain.Record
	soaCount := 0

	for {
		// Read 2-byte length
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		pLen := int(lenBuf[0])<<8 | int(lenBuf[1])

		// Read packet
		pData := make([]byte, pLen)
		if _, err := io.ReadFull(conn, pData); err != nil {
			return nil, err
		}

		resBuffer := packet.NewBytePacketBuffer()
		resBuffer.Load(pData)

		resp := packet.NewDNSPacket()
		if err := resp.FromBuffer(resBuffer); err != nil {
			return nil, err
		}

		if resp.Header.ResCode != packet.RcodeNoError {
			return nil, fmt.Errorf("master returned error: %d", resp.Header.ResCode)
		}

		for _, ans := range resp.Answers {
			if ans.Type == packet.SOA {
				soaCount++
			}

			dRec, err := repository.ConvertPacketRecordToDomain(ans, zoneID)
			if err != nil {
				s.Logger.Warn("failed to convert packet record", "error", err)
				continue
			}
			dRec.TenantID = s.NodeID // Use NodeID as tenant proxy for catalog-provisioned zones
			records = append(records, dRec)
		}

		// AXFR ends when the second SOA is received
		if soaCount >= 2 {
			break
		}
	}

	return records, nil
}
