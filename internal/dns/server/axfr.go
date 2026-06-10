package server

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

// handleAXFR processes a DNS zone transfer (AXFR) request over TCP.
func (s *Server) handleAXFR(ctx context.Context, conn net.Conn, request *packet.DNSPacket, rawData []byte, buffer *packet.BytePacketBuffer) {
	defer packet.PutBuffer(buffer)
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Validate TSIG if present
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		// Validate TSIG key name (issue #261)
		if err := domain.ValidateTSIGName(tsig.Name); err != nil {
			s.Logger.Debug("AXFR failed: invalid TSIG key name", "key", tsig.Name, "error", err)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		key, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Debug("AXFR failed: unknown TSIG key", "key", tsig.Name, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, key.Secret); errVerify != nil {
			s.Logger.Warn("AXFR failed: TSIG verification failed", "error", errVerify, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	// Lookup zone (needed regardless of TSIG for AXFR streaming)
	zone, err := s.Repo.GetZone(ctx, q.Name)
	if err != nil {
		s.Logger.Error("AXFR failed to look up zone", "zone", q.Name, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
		return
	}
	if zone == nil {
		s.Logger.Warn("AXFR requested for non-existent zone", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 3) // NXDOMAIN
		return
	}

	// Issue #256: tenant authorization check for TSIG-authenticated requests
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		key := s.TsigKeys[tsig.Name]
		if key.TenantID != "" && key.TenantID != zone.TenantID {
			s.Logger.Warn("AXFR rejected: tenant mismatch", "key", tsig.Name, "zone", q.Name, "zone_tenant", zone.TenantID, "key_tenant", key.TenantID)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
	if errIter != nil {
		s.Logger.Error("AXFR failed to open record stream", "zone", zone.ID, "error", errIter)
		s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
		return
	}
	defer func() { _ = iter.Close() }()

	// First pass: find SOA record
	var soa domain.Record
	var foundSOA bool
	for iter.Next() {
		rec := iter.Record()
		if rec.Type == domain.TypeSOA {
			soa = rec
			foundSOA = true
			break
		}
	}
	if err := iter.Err(); err != nil {
		s.Logger.Error("AXFR failed during SOA lookup", "zone", zone.ID, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}
	if !foundSOA {
		s.Logger.Error("AXFR failed: zone has no SOA", "zone", zone.Name)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	s.Logger.Info("AXFR starting", "zone", zone.Name)

	// Stream SOA first
	s.sendAXFRRecord(conn, request.Header.ID, q, soa, 0)

	// Stream all non-SOA records
	index := 1
	for iter.Next() {
		rec := iter.Record()
		if rec.Type == domain.TypeSOA {
			continue
		}
		s.sendAXFRRecord(conn, request.Header.ID, q, rec, index)
		index++
	}
	if err := iter.Err(); err != nil {
		s.Logger.Error("AXFR failed during record streaming", "zone", zone.ID, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	// Stream SOA last
	s.sendAXFRRecord(conn, request.Header.ID, q, soa, index)
	s.Logger.Info("AXFR completed", "zone", zone.Name)
}

// sendAXFRRecord converts a domain.Record to a packet record and sends it over TCP.
func (s *Server) sendAXFRRecord(conn net.Conn, id uint16, q packet.DNSQuestion, rec domain.Record, index int) {
	pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
	if errConv != nil {
		s.Logger.Error("AXFR failed to convert record", "type", rec.Type, "error", errConv)
		return
	}

	response := packet.NewDNSPacket()
	response.Header.ID = id
	response.Header.Response = true
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, q)
	response.Answers = append(response.Answers, pRec)

	resBuffer := packet.GetBuffer()
	resBuffer.HasNames = true
	if errWrite := response.Write(resBuffer); errWrite != nil {
		s.Logger.Error("AXFR failed to write response", "error", errWrite)
		packet.PutBuffer(resBuffer)
		return
	}
	resData := resBuffer.Buf[:resBuffer.Position()]

	resLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	if _, errW := conn.Write(fullResp); errW != nil {
		s.Logger.Error("AXFR connection broken", "error", errW)
		packet.PutBuffer(resBuffer)
		return
	}
	s.Logger.Debug("AXFR sent packet", "index", index, "type", pRec.Type)
	packet.PutBuffer(resBuffer)
	metrics.AXFRBytesTotal.Add(float64(len(fullResp)))
}

// sendTCPError sends a TCP DNS error response with the given RCODE.
func (s *Server) sendTCPError(conn net.Conn, id uint16, rcode uint8) {
	response := packet.NewDNSPacket()
	response.Header.ID = id
	response.Header.Response = true
	response.Header.ResCode = rcode
	resBuffer := packet.GetBuffer()
	_ = response.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	resLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(resLen >> 8), byte(resLen & 0xFF)}, resData...)
	_, _ = conn.Write(fullResp)
	packet.PutBuffer(resBuffer)
}

// handleIXFR processes an incremental zone transfer (IXFR) request over TCP.
func (s *Server) handleIXFR(ctx context.Context, conn net.Conn, request *packet.DNSPacket, rawData []byte, buffer *packet.BytePacketBuffer) {
	defer packet.PutBuffer(buffer)
	q := request.Questions[0]
	if !strings.HasSuffix(q.Name, ".") {
		q.Name += "."
	}

	// Validate TSIG if present
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		// Validate TSIG key name (issue #261)
		if err := domain.ValidateTSIGName(tsig.Name); err != nil {
			s.Logger.Debug("IXFR failed: invalid TSIG key name", "key", tsig.Name, "error", err)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		key, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Debug("IXFR failed: unknown TSIG key", "key", tsig.Name, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, key.Secret); errVerify != nil {
			s.Logger.Warn("IXFR failed: TSIG verification failed", "error", errVerify, "zone", q.Name)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	// RFC 1995: The client's current SOA is in the Authority section
	if len(request.Authorities) == 0 || request.Authorities[0].Type != packet.SOA {
		s.Logger.Warn("IXFR requested without client SOA in Authority section", "name", q.Name)
		s.sendTCPError(conn, request.Header.ID, 1) // FORMERR
		return
	}
	clientSOA := request.Authorities[0]
	clientSerial := clientSOA.Serial

	// Lookup zone (needed regardless of TSIG for IXFR)
	zone, err := s.Repo.GetZone(ctx, q.Name)
	if err != nil || zone == nil {
		s.Logger.Warn("IXFR requested for non-existent zone", "name", q.Name, "error", err)
		s.sendTCPError(conn, request.Header.ID, 3) // NXDOMAIN
		return
	}

	// Issue #259: tenant authorization check for TSIG-authenticated requests
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		key := s.TsigKeys[tsig.Name]
		if key.TenantID != "" && key.TenantID != zone.TenantID {
			s.Logger.Warn("IXFR rejected: tenant mismatch", "key", tsig.Name, "zone", q.Name, "zone_tenant", zone.TenantID, "key_tenant", key.TenantID)
			s.sendTCPError(conn, request.Header.ID, 5) // NotAuth
			return
		}
	}

	// Get current SOA
	soaRecords, err := s.Repo.GetRecords(ctx, zone.Name, domain.TypeSOA, "")
	if err != nil || len(soaRecords) == 0 {
		s.Logger.Error("IXFR failed: zone has no SOA", "zone", zone.Name, "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}
	currentSOA := soaRecords[0]
	fields := strings.Fields(currentSOA.Content)
	if len(fields) < 3 {
		s.Logger.Error("IXFR failed: malformed SOA content", "zone", zone.Name, "content", currentSOA.Content)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	var currentSerial uint32
	if _, err := fmt.Sscanf(fields[2], "%d", &currentSerial); err != nil {
		s.Logger.Error("IXFR failed: invalid SOA serial", "zone", zone.Name, "serial", fields[2], "error", err)
		s.sendTCPError(conn, request.Header.ID, 2)
		return
	}

	if clientSerial == currentSerial {
		// Client is up to date, just send current SOA
		s.Logger.Info("IXFR client is up to date", "zone", zone.Name, "serial", clientSerial)
		pSOA, err := repository.ConvertDomainToPacketRecord(currentSOA)
		if err == nil {
			s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)
		}
		return
	}

	// Fetch changes since clientSerial using IXFR chain logic
	chunks, err := s.Repo.GetIXFRChain(ctx, zone.ID, clientSerial, currentSerial)

	// RFC 1995: Verify full IXFR chain continuity
	// Note: clientSerial+1 wraps to 0 when clientSerial is max uint32.
	// In that case, we can only validate if chunks starts at 0 (which is valid after wrap).
	historyValid := false
	if len(chunks) > 0 {
		if clientSerial == math.MaxUint32 {
			// Overflow case: client is at max uint32, first chunk must be at 0
			// Sequential check below will validate the chain
			historyValid = chunks[0].Serial == 0
		} else {
			historyValid = chunks[0].Serial == clientSerial+1
		}
	}
	if historyValid {
		for i := 1; i < len(chunks); i++ {
			// Use uint32 wrap-around aware comparison for sequential serials
			expectedSerial := chunks[i-1].Serial + 1
			if chunks[i].Serial != expectedSerial {
				historyValid = false
				break
			}
		}
	}
	// Verify the last chunk reaches currentSerial (rejects truncated chains)
	if historyValid && len(chunks) > 0 {
		if chunks[len(chunks)-1].Serial != currentSerial {
			historyValid = false
		}
	}

	if err != nil {
		s.Logger.Warn("IXFR chain query failed, falling back to AXFR", "zone", zone.Name, "error", err)
	} else if !historyValid {
		s.Logger.Info("IXFR history gap detected, falling back to AXFR",
			"zone", zone.Name, "client_serial", clientSerial)

		// RFC 1995: If IXFR is not possible, fall back to AXFR sequence using streaming
		iter, errIter := s.Repo.ListRecordsForZoneStreaming(ctx, zone.ID, zone.TenantID)
		if errIter != nil {
			s.Logger.Error("IXFR/AXFR fallback failed to open record stream", "zone", zone.Name, "error", errIter)
			s.sendTCPError(conn, request.Header.ID, 2) // SERVFAIL
			return
		}
		defer func() { _ = iter.Close() }()

		pSOA, errConv := repository.ConvertDomainToPacketRecord(currentSOA)
		if errConv != nil {
			s.Logger.Error("IXFR/AXFR fallback failed to convert SOA", "zone", zone.Name, "error", errConv)
			s.sendTCPError(conn, request.Header.ID, 2)
			return
		}

		// 2. Send Current SOA (start)
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)

		// 3. Stream all records in the zone
		for iter.Next() {
			rec := iter.Record()
			if rec.Type == domain.TypeSOA {
				continue
			}
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				s.sendSingleRecordResponse(conn, request.Header.ID, q, pRec)
			}
		}
		if err := iter.Err(); err != nil {
			s.Logger.Error("IXFR/AXFR fallback failed during streaming", "zone", zone.Name, "error", err)
			s.sendTCPError(conn, request.Header.ID, 2)
			return
		}

		// 4. Send Current SOA (end)
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pSOA)
		return
	}

	s.Logger.Info("IXFR starting", "zone", zone.Name, "from", clientSerial, "to", currentSerial, "chunks", len(chunks))

	// Send Current SOA (marks start of IXFR)
	pCurrentSOA, err := repository.ConvertDomainToPacketRecord(currentSOA)
	if err == nil {
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pCurrentSOA)
	}

	// Send each chunk
	for _, chunk := range chunks {
		// RFC 1995: IXFR sequence is [SOA(new), (SOA(old), deleted..., SOA(new), added...)*, SOA(new)]
		// Note: The outer handleIXFR sends the first and last SOA(new).

		// 1. Send Old SOA (from deletions if available to preserve fields)
		var oldSOA domain.Record
		foundOld := false
		for _, r := range chunk.Deleted {
			if r.Type == domain.TypeSOA {
				oldSOA = r
				foundOld = true
				break
			}
		}
		if !foundOld {
			oldSOA = currentSOA
			// We don't have the original old SOA in the chunk, fallback to current but with old serial
			// (This shouldn't happen with our bounded delta logger)
			parts := strings.Fields(oldSOA.Content)
			if len(parts) >= 3 {
				parts[2] = fmt.Sprintf("%d", clientSerial)
				oldSOA.Content = strings.Join(parts, " ")
			}
		}
		pOldSOA, err := repository.ConvertDomainToPacketRecord(oldSOA)
		if err == nil {
			s.sendSingleRecordResponse(conn, request.Header.ID, q, pOldSOA)
		}

		// 2. Send Deletions
		for _, rec := range chunk.Deleted {
			if rec.Type == domain.TypeSOA {
				continue
			}
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				s.sendSingleRecordResponse(conn, request.Header.ID, q, pRec)
			}
		}

		// 3. Send New SOA (from additions)
		var newSOA domain.Record
		foundNew := false
		for _, r := range chunk.Added {
			if r.Type == domain.TypeSOA {
				newSOA = r
				foundNew = true
				break
			}
		}
		if !foundNew {
			newSOA = currentSOA
			parts := strings.Fields(newSOA.Content)
			if len(parts) >= 3 {
				parts[2] = fmt.Sprintf("%d", chunk.Serial)
				newSOA.Content = strings.Join(parts, " ")
			}
		}
		pNewSOA, err := repository.ConvertDomainToPacketRecord(newSOA)
		if err == nil {
			s.sendSingleRecordResponse(conn, request.Header.ID, q, pNewSOA)
		}

		// 4. Send Additions
		for _, rec := range chunk.Added {
			if rec.Type == domain.TypeSOA {
				continue
			}
			pRec, errConv := repository.ConvertDomainToPacketRecord(rec)
			if errConv == nil {
				s.sendSingleRecordResponse(conn, request.Header.ID, q, pRec)
			}
		}

		// For the next chunk, clientSerial is now this chunk's Serial
		clientSerial = chunk.Serial
	}

	// Send Current SOA (marks end of IXFR)
	if err == nil {
		s.sendSingleRecordResponse(conn, request.Header.ID, q, pCurrentSOA)
	}
	s.Logger.Info("IXFR completed", "zone", zone.Name)
}

// sendSingleRecordResponse sends a TCP DNS response containing a single resource record.
func (s *Server) sendSingleRecordResponse(conn net.Conn, id uint16, q packet.DNSQuestion, rec packet.DNSRecord) {
	resp := packet.NewDNSPacket()
	resp.Header.ID = id
	resp.Header.Response = true
	resp.Header.AuthoritativeAnswer = true
	resp.Questions = append(resp.Questions, q)
	resp.Answers = append(resp.Answers, rec)

	resBuffer := packet.GetBuffer()
	_ = resp.Write(resBuffer)
	resData := resBuffer.Buf[:resBuffer.Position()]
	// TCP requires 2-byte length prefix
	fullLen := uint16(len(resData)) // #nosec G115
	fullResp := append([]byte{byte(fullLen >> 8), byte(fullLen & 0xFF)}, resData...)
	_, _ = conn.Write(fullResp)
	packet.PutBuffer(resBuffer)
}