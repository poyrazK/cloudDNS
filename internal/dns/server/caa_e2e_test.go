package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestCAAEndToEnd(t *testing.T) {
	repo := &mockServerRepo{}
	dnsAddr := "127.0.0.1:10057"
	dnsSrv := NewServer(dnsAddr, repo, nil)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go func() {
		if err := dnsSrv.Run(ctx); err != nil {
			// t.Logf("DNS server stopped: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Setup Zone and CAA Record
	zoneName := "caa.test."
	repo.CreateZone(context.Background(), &domain.Zone{ID: "zone-caa", Name: zoneName})
	
	// CAA record format: [flag] [tag] "[value]"
	caaContent := "0 issue \"letsencrypt.org\""
	repo.CreateRecord(context.Background(), &domain.Record{
		ID:      "rec-caa-1",
		ZoneID:  "zone-caa",
		Name:    zoneName,
		Type:    domain.TypeCAA,
		Content: caaContent,
		TTL:     3600,
	})

	// Query for CAA
	query := packet.NewDNSPacket()
	query.Header.ID = 1234
	query.Header.RecursionDesired = true
	query.Questions = append(query.Questions, packet.DNSQuestion{
		Name:  zoneName,
		QType: packet.CAA,
	})

	// Debug: Check if repo has the record
	recs, _ := repo.GetRecords(context.Background(), zoneName, domain.TypeCAA, "")
	if len(recs) == 0 {
		t.Logf("Repo is empty for CAA query on %s", zoneName)
		allRecs, _ := repo.ListRecordsForZone(context.Background(), "zone-caa", "")
		for _, r := range allRecs {
			t.Logf("Found record in zone: %s %s %s", r.Name, r.Type, r.Content)
		}
	} else {
		t.Logf("Repo returned %d records for CAA", len(recs))
	}

	buf := packet.GetBuffer()
	_ = query.Write(buf)
	
	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(buf.Buf[:buf.Position()])
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	respBuf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	resPacket := packet.NewDNSPacket()
	resBufWrapper := packet.GetBuffer()
	resBufWrapper.Load(respBuf[:n])
	if err := resPacket.FromBuffer(resBufWrapper); err != nil {
		t.Fatalf("Failed to parse response packet: %v", err)
	}

	if len(resPacket.Answers) == 0 {
		t.Fatalf("Expected 1 answer, got 0")
	}

	ans := resPacket.Answers[0]
	if ans.Type != packet.CAA {
		t.Errorf("Expected answer type CAA, got %v", ans.Type)
	}

	if ans.CAAFlag != 0 {
		t.Errorf("Expected CAA flag 0, got %d", ans.CAAFlag)
	}
	if ans.CAATag != "issue" {
		t.Errorf("Expected CAA tag 'issue', got %s", ans.CAATag)
	}
	if ans.CAAValue != "letsencrypt.org" {
		t.Errorf("Expected CAA value 'letsencrypt.org', got %s", ans.CAAValue)
	}
}

func TestCAAUpdateEndToEnd(t *testing.T) {
	repo := &mockServerRepo{}
	dnsAddr := "127.0.0.1:10058"
	dnsSrv := NewServer(dnsAddr, repo, nil)
	dnsSrv.DisableAsync = true
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go func() {
		if err := dnsSrv.Run(ctx); err != nil {
			// t.Logf("DNS server stopped: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// Setup Zone
	zoneName := "update-caa.test."
	repo.CreateZone(context.Background(), &domain.Zone{ID: "zone-update-caa", Name: zoneName})
	
	// SOA is required for dynamic updates logic in this implementation
	repo.CreateRecord(context.Background(), &domain.Record{
		ID:      "soa-1",
		ZoneID:  "zone-update-caa",
		Name:    zoneName,
		Type:    domain.TypeSOA,
		Content: "ns1.update-caa.test. admin.update-caa.test. 2023010101 3600 600 604800 300",
		TTL:     3600,
	})

	// 1. Send UPDATE to add CAA record
	update := packet.NewDNSPacket()
	update.Header.ID = 5678
	update.Header.Opcode = packet.OpcodeUpdate
	
	// Zone section
	update.Questions = append(update.Questions, packet.DNSQuestion{
		Name:  zoneName,
		QType: packet.SOA,
	})

	// Update section (Authorities in RFC 2136 packet)
	caaRec := packet.DNSRecord{
		Name:     "caa." + zoneName,
		Type:     packet.CAA,
		Class:    1, // IN (Add)
		TTL:      300,
		CAAFlag:  0,
		CAATag:   "issue",
		CAAValue: "globalsign.com",
	}
	update.Authorities = append(update.Authorities, caaRec)

	buf := packet.GetBuffer()
	_ = update.Write(buf)
	
	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(buf.Buf[:buf.Position()])
	if err != nil {
		t.Fatalf("Failed to send update: %v", err)
	}

	respBuf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read update response: %v", err)
	}

	resPacket := packet.NewDNSPacket()
	resBufWrapper := packet.GetBuffer()
	resBufWrapper.Load(respBuf[:n])
	if err := resPacket.FromBuffer(resBufWrapper); err != nil {
		t.Fatalf("Failed to parse update response packet: %v", err)
	}

	if resPacket.Header.ResCode != packet.RcodeNoError {
		t.Fatalf("Update failed with RCODE %d", resPacket.Header.ResCode)
	}

	// 2. Query to verify CAA record was added
	query := packet.NewDNSPacket()
	query.Header.ID = 9012
	query.Questions = append(query.Questions, packet.DNSQuestion{
		Name:  "caa." + zoneName,
		QType: packet.CAA,
	})

	buf.Reset()
	_ = query.Write(buf)
	
	_, err = conn.Write(buf.Buf[:buf.Position()])
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	n, err = conn.Read(respBuf)
	if err != nil {
		t.Fatalf("Failed to read query response: %v", err)
	}

	resPacket = packet.NewDNSPacket()
	resBufWrapper.Reset()
	resBufWrapper.Load(respBuf[:n])
	_ = resPacket.FromBuffer(resBufWrapper)

	if len(resPacket.Answers) == 0 {
		t.Fatalf("Expected 1 answer, got 0")
	}

	ans := resPacket.Answers[0]
	if ans.CAAValue != "globalsign.com" {
		t.Errorf("Expected CAA value 'globalsign.com', got %s", ans.CAAValue)
	}
}
