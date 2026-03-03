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

func (s *Server) refreshZone(zone *domain.Zone) {
	if zone.MasterServer == "" {
		s.Logger.Warn("slave zone has no master server configured", "zone", zone.Name)
		return
	}

	masterAddr := net.JoinHostPort(zone.MasterServer, "53")
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
	records, err := s.Repo.GetRecords(context.Background(), zone.Name, domain.TypeSOA, "")
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
		if err := s.performIXFR(zone, masterAddr, localSerial); err == nil {
			s.Logger.Info("IXFR successful", "zone", zone.Name)
			return
		} else {
			s.Logger.Warn("IXFR failed, falling back to AXFR", "zone", zone.Name, "error", err)
		}
	}

	if err := s.performAXFR(zone, masterAddr); err != nil {
		s.Logger.Error("AXFR failed", "zone", zone.Name, "error", err)
	}
}

func (s *Server) performIXFR(zone *domain.Zone, masterAddr string, localSerial uint32) error {
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
	localSOARecords, err := s.Repo.GetRecords(context.Background(), zone.Name, domain.TypeSOA, "")
	if err == nil && len(localSOARecords) > 0 {
		pSOA, errConv := repository.ConvertDomainToPacketRecord(localSOARecords[0])
		if errConv == nil {
			req.Authorities = append(req.Authorities, pSOA)
		}
	}

	buffer := packet.NewBytePacketBuffer()
	if err := req.Write(buffer); err != nil {
		return err
	}
	data := buffer.Buf[:buffer.Position()]
	prefix := []byte{byte(len(data) >> 8), byte(len(data) & 0xFF)}
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
				if !isIncremental && soaCount >= 1 {
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

	ctx := context.Background()
	if !isIncremental {
		// AXFR Fallback
		var newRecords []domain.Record
		for _, r := range allRecords {
			dRec, errConv := repository.ConvertPacketRecordToDomain(r, zone.ID)
			if errConv == nil {
				dRec.TenantID = zone.TenantID
				newRecords = append(newRecords, dRec)
			}
		}
		_ = s.Repo.DeleteRecordsForZone(ctx, zone.ID)
		return s.Repo.BatchCreateRecords(ctx, newRecords)
	}

	// Incremental logic: Apply Deletions then Additions
	// The sequence is [SOA(old), deleted..., SOA(new), added...]
	deleting := false
	for _, r := range allRecords {
		dRec, errConv := repository.ConvertPacketRecordToDomain(r, zone.ID)
		if errConv != nil {
			continue
		}
		if r.Type == packet.SOA {
			deleting = !deleting
			if !deleting {
				// This is SOA(new), save it to update local serial
				dRec.TenantID = zone.TenantID
				_ = s.Repo.CreateRecord(ctx, &dRec)
			} else {
				// This is SOA(old), delete it
				_ = s.Repo.DeleteRecordSpecific(ctx, zone.ID, dRec.Name, dRec.Type, dRec.Content)
			}
			continue
		}
		if deleting {
			_ = s.Repo.DeleteRecordSpecific(ctx, zone.ID, dRec.Name, dRec.Type, dRec.Content)
		} else {
			dRec.TenantID = zone.TenantID
			_ = s.Repo.CreateRecord(ctx, &dRec)
		}
	}

	return nil
}
}

func (s *Server) performAXFR(zone *domain.Zone, masterAddr string) error {
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
	prefix := []byte{byte(len(data) >> 8), byte(len(data) & 0xFF)}
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
	ctx := context.Background()
	if err := s.Repo.DeleteRecordsForZone(ctx, zone.ID); err != nil {
		return fmt.Errorf("failed to clear old records: %w", err)
	}

	return s.Repo.BatchCreateRecords(ctx, newRecords)
}
