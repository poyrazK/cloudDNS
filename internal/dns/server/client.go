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
			fmt.Sscanf(parts[2], "%d", &localSerial)
		}
	}

	s.Logger.Info("comparing serials", "zone", zone.Name, "local", localSerial, "master", masterSOA.Serial)

	if localSerial >= masterSOA.Serial && localSerial != 0 {
		s.Logger.Info("zone is up to date", "zone", zone.Name)
		return
	}

	// 3. Initiate transfer (Try IXFR, fall back to AXFR)
	// For now, let's implement AXFR first as it's simpler and always works
	if err := s.performAXFR(zone, masterAddr); err != nil {
		s.Logger.Error("AXFR failed", "zone", zone.Name, "error", err)
	}
}

func (s *Server) performAXFR(zone *domain.Zone, masterAddr string) error {
	s.Logger.Info("starting AXFR", "zone", zone.Name, "master", masterAddr)

	conn, err := net.DialTimeout("tcp", masterAddr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

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
	// We need a way to delete all records for a zone.
	// I'll add DeleteRecordsForZone to the repository.
	if err := s.Repo.DeleteRecordsByName(ctx, zone.ID, ""); err != nil {
		return fmt.Errorf("failed to clear old records: %w", err)
	}

	return s.Repo.BatchCreateRecords(ctx, newRecords)
}
