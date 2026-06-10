package server

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/infrastructure/metrics"
)

// handleNotify processes a DNS NOTIFY (RFC 1996) and triggers a zone refresh if needed.
func (s *Server) handleNotify(ctx context.Context, request *packet.DNSPacket, clientIP string, sendFn func([]byte) error) error {
	if len(request.Questions) == 0 {
		s.Logger.Warn("received NOTIFY without questions", "from", clientIP)
		return nil
	}
	s.Logger.Info("received NOTIFY", "zone", request.Questions[0].Name, "from", clientIP)
	metrics.NotifiesTotal.WithLabelValues(request.Questions[0].Name, "accepted").Inc()

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeNotify
	response.Header.AuthoritativeAnswer = true
	response.Questions = append(response.Questions, request.Questions[0])

	// For slave zones, validate source is the configured master before triggering refresh
	zone, err := s.Repo.GetZone(ctx, request.Questions[0].Name)
	if err != nil {
		s.Logger.Error("failed to fetch zone for notify", "zone", request.Questions[0].Name, "error", err)
	}
	if zone != nil && zone.Role == "slave" && zone.MasterServer != "" {
		if !isAuthorizedNotifier(clientIP, zone.MasterServer) {
			s.Logger.Warn("NOTIFY rejected: unauthorized source", "from", clientIP, "master", zone.MasterServer)
		} else if !s.DisableAsync {
			go func(zoneName string) {
				select {
				case <-ctx.Done():
					return
				case <-s.done:
					return
				default:
				}
				if z, err := s.Repo.GetZone(ctx, zoneName); err == nil && z != nil {
					s.refreshZone(ctx, z)
				}
			}(request.Questions[0].Name)
		}
	}

	response.Header.ResCode = packet.RcodeNoError
	return s.sendUpdateResponse(response, sendFn)
}

// isAuthorizedNotifier checks if the source IP is authorized to send NOTIFY for the zone.
func isAuthorizedNotifier(clientIP, masterServer string) bool {
	// Extract host from masterServer (may be "host:port" format)
	masterHost, _, err := net.SplitHostPort(masterServer)
	if err != nil {
		masterHost = masterServer // No port in config, use as-is
	}

	// If master is an IP, compare directly
	if net.ParseIP(masterHost) != nil {
		return clientIP == masterHost
	}

	// Master is a hostname — resolve and compare IPs
	addrs, err := net.ResolveTCPAddr("tcp", masterHost+":0")
	if err != nil {
		return false
	}
	clientParsed := net.ParseIP(clientIP)
	if clientParsed == nil {
		return false
	}
	return clientParsed.Equal(addrs.IP)
}

// handleUpdate processes a DNS dynamic update (RFC 2136) request.
func (s *Server) handleUpdate(ctx context.Context, request *packet.DNSPacket, rawData []byte, clientIP string, sendFn func([]byte) error) error {
	s.Logger.Info("handling dynamic update", "id", request.Header.ID, "client", clientIP)

	response := packet.NewDNSPacket()
	response.Header.ID = request.Header.ID
	response.Header.Response = true
	response.Header.Opcode = packet.OpcodeUpdate

	// 1. Validate TSIG if present
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		// Validate TSIG key name (issue #261)
		if err := domain.ValidateTSIGName(tsig.Name); err != nil {
			s.Logger.Debug("update failed: invalid TSIG key name", "key", tsig.Name, "error", err)
			response.Header.ResCode = packet.RcodeNotAuth
			return s.sendUpdateResponse(response, sendFn)
		}
		key, ok := s.TsigKeys[tsig.Name]
		if !ok {
			s.Logger.Debug("update failed: unknown TSIG key", "key", tsig.Name)
			response.Header.ResCode = packet.RcodeNotAuth
			return s.sendUpdateResponse(response, sendFn)
		}
		if errVerify := request.VerifyTSIG(rawData, request.TSIGStart, key.Secret); errVerify != nil {
			s.Logger.Warn("update failed: TSIG verification failed", "error", errVerify)
			response.Header.ResCode = packet.RcodeNotAuth
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 2. Validate Zone Section (ZOCOUNT must be 1)
	if len(request.Questions) != 1 {
		s.Logger.Warn("update failed: ZOCOUNT != 1", "count", len(request.Questions))
		response.Header.ResCode = packet.RcodeFormErr
		return s.sendUpdateResponse(response, sendFn)
	}

	zone := request.Questions[0]
	if !strings.HasSuffix(zone.Name, ".") {
		zone.Name += "."
	}
	response.Questions = append(response.Questions, zone)

	dbZone, _ := s.Repo.GetZone(ctx, zone.Name)
	if dbZone == nil {
		s.Logger.Warn("update failed: not authoritative for zone", "zone", zone.Name)
		response.Header.ResCode = packet.RcodeNotAuth
		return s.sendUpdateResponse(response, sendFn)
	}

	// Issue #256: tenant authorization check for TSIG-authenticated updates
	if request.TSIGStart != -1 && len(request.Resources) > 0 {
		tsig := request.Resources[len(request.Resources)-1]
		key := s.TsigKeys[tsig.Name]
		if key.TenantID != "" && key.TenantID != dbZone.TenantID {
			s.Logger.Warn("update rejected: tenant mismatch", "key", tsig.Name, "zone", zone.Name, "zone_tenant", dbZone.TenantID, "key_tenant", key.TenantID)
			response.Header.ResCode = packet.RcodeNotAuth
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 2. Prerequisite Checks (PRCOUNT)
	for _, pr := range request.Answers {
		if errPrereq := s.checkPrerequisite(ctx, pr); errPrereq != nil {
			s.Logger.Warn("update failed: prerequisite mismatch", "pr", pr.Name, "error", errPrereq)
			var uErr updateError
			if errors.As(errPrereq, &uErr) {
				response.Header.ResCode = uint8(uErr.rcode) // #nosec G115
			} else {
				response.Header.ResCode = packet.RcodeServFail
			}
			return s.sendUpdateResponse(response, sendFn)
		}
	}

	// 3. Prepare Updates (UPCOUNT)
	operations := make([]domain.UpdateOperation, 0, len(request.Authorities))
	changes := make([]domain.ZoneChange, 0, len(request.Authorities))

	for _, up := range request.Authorities {
		op, change, errPrep := s.prepareUpdate(dbZone.ID, up)
		if errPrep != nil {
			s.Logger.Error("update failed: conversion error", "error", errPrep)
			response.Header.ResCode = packet.RcodeServFail
			return s.sendUpdateResponse(response, sendFn)
		}
		operations = append(operations, op)
		changes = append(changes, change)
	}

	// 4. Handle Serial Increment and Atomic Apply
	if len(changes) > 0 {
		// Apply everything in a single transaction
		// Repository fetches current SOA serial inside the tx and increments atomically
		newSerial, errApply := s.Repo.ApplyZoneUpdate(ctx, dbZone.ID, operations, changes)
		if errApply != nil {
			s.Logger.Error("atomic update failed", "zone", dbZone.Name, "error", errApply)
			response.Header.ResCode = packet.RcodeServFail
			return s.sendUpdateResponse(response, sendFn)
		}

		if newSerial > 0 {
			s.Logger.Info("dynamic update successful", "zone", zone.Name, "new_serial", newSerial)
		} else {
			s.Logger.Info("dynamic update applied without serial increment (no SOA found)", "zone", zone.Name)
		}

		s.Cache.Flush()
		if s.Redis != nil {
			_ = s.Redis.Invalidate(ctx, dbZone.TenantID, zone.Name, "")
		}
		if !s.DisableAsync {
			go s.notifySlaves(ctx, zone.Name)
		}
		response.Header.ResCode = packet.RcodeNoError
		return s.sendUpdateResponse(response, sendFn)
	}

	// 5. Success (no changes)
	response.Header.ResCode = packet.RcodeNoError
	s.Logger.Info("dynamic update processed", "zone", zone.Name)
	s.Cache.Flush()
	if s.Redis != nil {
		_ = s.Redis.Invalidate(ctx, dbZone.TenantID, zone.Name, "")
	}

	if !s.DisableAsync {
		go s.notifySlaves(ctx, zone.Name)
	}

	return s.sendUpdateResponse(response, sendFn)
}

// sendUpdateResponse serializes and sends a DNS UPDATE response.
func (s *Server) sendUpdateResponse(resp *packet.DNSPacket, sendFn func([]byte) error) error {
	resBuffer := packet.GetBuffer()
	defer packet.PutBuffer(resBuffer)
	_ = resp.Write(resBuffer)
	return sendFn(resBuffer.Buf[:resBuffer.Position()])
}

// checkPrerequisite evaluates a DNS UPDATE prerequisite record (RFC 2136 Section 2.4).
func (s *Server) checkPrerequisite(ctx context.Context, pr packet.DNSRecord) error {
	qTypeStr := queryTypeToRecordType(pr.Type)
	records, errRecs := s.Repo.GetRecords(ctx, pr.Name, qTypeStr, "")
	if errRecs != nil {
		return updateError{rcode: int(packet.RcodeServFail), msg: "failed to fetch records for prerequisite check"}
	}

	switch pr.Class {
	case 255: // ANY
		if pr.Type == 255 { // ANY
			if len(records) == 0 {
				return updateError{rcode: int(packet.RcodeNxDomain), msg: "name not in use"}
			}
		} else {
			if len(records) == 0 {
				return updateError{rcode: int(packet.RcodeNxRRSet), msg: "rrset does not exist"}
			}
		}
	case 254: // NONE
		if pr.Type == 255 { // ANY
			if len(records) > 0 {
				return updateError{rcode: int(packet.RcodeYxDomain), msg: "name in use"}
			}
		} else {
			if len(records) > 0 {
				return updateError{rcode: int(packet.RcodeYxRRSet), msg: "rrset exists"}
			}
		}
	default:
		if len(records) == 0 {
			return updateError{rcode: int(packet.RcodeNxRRSet), msg: "rrset does not exist"}
		}
	}

	return nil
}

// prepareUpdate converts a DNS record update from an RFC 2136 message into an internal
// atomic operation and its corresponding historical change record.
func (s *Server) prepareUpdate(zoneID string, up packet.DNSRecord) (domain.UpdateOperation, domain.ZoneChange, error) {
	upName := up.Name
	if !strings.HasSuffix(upName, ".") {
		upName += "."
	}

	op := domain.UpdateOperation{}
	dRec, errConv := repository.ConvertPacketRecordToDomain(up, zoneID)
	if errConv != nil && up.Class != 255 { // Class ANY might fail conversion if RDATA is missing
		return op, domain.ZoneChange{}, errConv
	}

	switch up.Class {
	case 255: // ANY: Delete RRset (RFC 2136 Section 2.5.2)
		if up.Type == 255 {
			op.Action = domain.ActionDeleteAll
		} else {
			op.Action = domain.ActionDeleteRRSet
		}
		op.Record = domain.Record{
			ZoneID: zoneID,
			Name:   upName,
			Type:   domain.RecordType(up.Type.String()),
		}
	case 254: // NONE: Delete specific record (RFC 2136 Section 2.5.4)
		op.Action = domain.ActionDeleteSpecific
		op.Record = dRec
	default: // Add record (RFC 2136 Section 2.5.1)
		op.Action = domain.ActionAdd
		if dRec.ID == "" {
			var bid [16]byte
			_, _ = crand.Read(bid[:])
			dRec.ID = fmt.Sprintf("%d-%x", time.Now().UnixNano(), bid)
		}
		if dRec.CreatedAt.IsZero() {
			dRec.CreatedAt = time.Now()
			dRec.UpdatedAt = time.Now()
		}
		op.Record = dRec
	}

	// Prepare historical change record for IXFR
	var rb [8]byte
	_, _ = crand.Read(rb[:])
	randomPart := binary.LittleEndian.Uint64(rb[:])
	change := domain.ZoneChange{
		ID:        fmt.Sprintf("%d-%x", time.Now().UnixNano(), randomPart),
		ZoneID:    zoneID,
		Name:      upName,
		Type:      domain.RecordType(up.Type.String()),
		TTL:       int(up.TTL),
		CreatedAt: time.Now(),
	}
	if op.Action == domain.ActionAdd {
		change.Action = "ADD"
		change.Content = op.Record.Content
		change.Priority = op.Record.Priority
	} else {
		change.Action = "DELETE"
		if op.Action == domain.ActionDeleteSpecific {
			change.Content = op.Record.Content
		}
	}

	return op, change, nil
}

// notifySlaves sends DNS NOTIFY messages to all slave servers configured for a zone.
func (s *Server) notifySlaves(ctx context.Context, zoneName string) {
	select {
	case <-ctx.Done():
		return
	case <-s.done:
		return
	default:
	}
	dbZone, errZone := s.Repo.GetZone(ctx, zoneName)
	if errZone != nil || dbZone == nil {
		return
	}

	nsRecords, errNS := s.Repo.GetRecords(ctx, zoneName, domain.TypeNS, "")
	if errNS != nil {
		return
	}

	for _, ns := range nsRecords {
		ips, errIPs := s.Repo.GetIPsForName(ctx, ns.Content, "")
		if errIPs != nil || len(ips) == 0 {
			continue
		}

		for _, ip := range ips {
			// Skip logic: only skip if it's EXACTLY the same host:port
			targetPort := 53
			if s.NotifyPortOverride > 0 {
				targetPort = s.NotifyPortOverride
			}

			targetAddr := net.JoinHostPort(ip, fmt.Sprintf("%d", targetPort))
			if s.Addr == targetAddr {
				continue
			}

			s.Logger.Info("sending NOTIFY", "zone", zoneName, "slave", targetAddr)

			notify := packet.NewDNSPacket()
			// Use crand for secure NOTIFY ID (G404)
			var bid [2]byte
			_, _ = crand.Read(bid[:])
			notify.Header.ID = binary.LittleEndian.Uint16(bid[:])

			notify.Header.Opcode = packet.OpcodeNotify
			notify.Header.AuthoritativeAnswer = true
			notify.Questions = append(notify.Questions, packet.DNSQuestion{
				Name:  zoneName,
				QType: packet.SOA,
			})

			buf := packet.GetBuffer()
			_ = notify.Write(buf)
			data := buf.Buf[:buf.Position()]

			conn, errDial := net.Dial("udp", targetAddr)
			if errDial == nil {
				_, _ = conn.Write(data)
				_ = conn.Close()
			}
			packet.PutBuffer(buf)
		}
	}
}