package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/api"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestEndToEndDNSAdvanced(t *testing.T) {
	// 1. Setup Stack with Mock Repo (or real PG if we wanted even more integration)
	repo := &mockServerRepo{}
	svc := services.NewDNSService(repo, nil)
	dnsAddr := "127.0.0.1:10056"
	apiAddr := "127.0.0.1:18081"

	dnsSrv := NewServer(dnsAddr, repo, nil)
	go func() {
		_ = dnsSrv.Run()
	}()

	apiHandler := api.NewAPIHandler(svc, repo)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)
	apiSrv := &http.Server{Addr: apiAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		_ = apiSrv.ListenAndServe()
	}()

	// Wait for servers to start
	time.Sleep(500 * time.Millisecond)
	defer func() {
		_ = apiSrv.Shutdown(context.Background())
	}()

	// 2. Setup Authentication and Zone
	testKey := "cdns_test_key_1234567890"
	hash := sha256.Sum256([]byte(testKey))
	keyHash := hex.EncodeToString(hash[:])
	_ = repo.CreateAPIKey(context.Background(), &domain.APIKey{
		ID: "test-key-id", TenantID: "admin", Role: domain.RoleAdmin, Active: true, KeyHash: keyHash,
	})

	authHeader := "Bearer " + testKey

	zoneReq := domain.Zone{Name: "advanced.test.", TenantID: "admin"}
	body, err := json.Marshal(zoneReq)
	if err != nil {
		t.Fatalf("Failed to marshal zone req: %v", err)
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/zones", apiAddr), bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create req: %v", err)
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to create zone: %v", err)
	}
	var createdZone domain.Zone
	if decErr := json.NewDecoder(resp.Body).Decode(&createdZone); decErr != nil {
		t.Fatalf("Failed to decode zone: %v", decErr)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create zone: expected 201, got %d", resp.StatusCode)
	}

	records := []domain.Record{
		{Name: "a.advanced.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300, ZoneID: createdZone.ID},
		{Name: "*.advanced.test.", Type: domain.TypeTXT, Content: "wildcard", TTL: 300, ZoneID: createdZone.ID},
	}
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("Failed to marshal record: %v", err)
		}
		req2, err := http.NewRequest("POST", fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID), bytes.NewBuffer(b))
		if err != nil {
			t.Fatalf("Failed to build request: %v", err)
		}
		req2.Header.Set("Authorization", authHeader)
		req2.Header.Set("Content-Type", "application/json")
		if resp2, err2 := client.Do(req2); err2 == nil {
			if cerr := resp2.Body.Close(); cerr != nil {
				t.Fatalf("Failed to close response: %v", cerr)
			}
		} else {
			t.Fatalf("Failed to create record %s: %v", r.Name, err2)
		}
	}

	// 3. Test Wildcard Resolution
	query := packet.NewDNSPacket()
	query.Questions = append(query.Questions, packet.DNSQuestion{Name: "anything.advanced.test.", QType: packet.TXT})
	qBuf := packet.NewBytePacketBuffer()
	if err := query.Write(qBuf); err != nil {
		t.Fatalf("Failed to write to buffer: %v", err)
	}

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS: %v", err)
	}
	if _, err := conn.Write(qBuf.Buf[:qBuf.Position()]); err != nil {
		t.Fatalf("Failed to write udp: %v", err)
	}
	resBuf := make([]byte, 1024)
	n, err := conn.Read(resBuf)
	if err != nil {
		t.Fatalf("Failed to read udp res: %v", err)
	}

	res := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	pBuf.Load(resBuf[:n])
	if err := res.FromBuffer(pBuf); err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	if len(res.Answers) == 0 || res.Answers[0].Txt != "wildcard" {
		t.Errorf("Wildcard E2E failed")
	}
	if cerr := conn.Close(); cerr != nil {
		t.Fatalf("Failed to close TCP conn: %v", cerr)
	}

	// 4. Test AXFR over TCP
	tcpConn, err := net.Dial("tcp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS TCP: %v", err)
	}
	axfrQuery := packet.NewDNSPacket()
	axfrQuery.Header.ID = 0x1234
	axfrQuery.Questions = append(axfrQuery.Questions, packet.DNSQuestion{Name: "advanced.test.", QType: packet.AXFR})
	aqBuf := packet.NewBytePacketBuffer()
	if err := axfrQuery.Write(aqBuf); err != nil {
		t.Fatalf("Failed to write axfr qbuf: %v", err)
	}

	data := aqBuf.Buf[:aqBuf.Position()]
	fullData := append([]byte{byte(len(data) >> 8), byte(len(data) & 0xFF)}, data...)
	if _, err := tcpConn.Write(fullData); err != nil {
		t.Fatalf("Failed to write axfr req: %v", err)
	}

	// Read first SOA
	lenB := make([]byte, 2)
	if _, err := tcpConn.Read(lenB); err != nil {
		t.Fatalf("Failed to read axfr length: %v", err)
	}
	axfrRLen := uint16(lenB[0])<<8 | uint16(lenB[1])
	axfrRData := make([]byte, axfrRLen)
	if _, err := tcpConn.Read(axfrRData); err != nil {
		t.Fatalf("Failed to read axfr data: %v", err)
	}

	axfrRes := packet.NewDNSPacket()
	arb := packet.NewBytePacketBuffer()
	arb.Load(axfrRData)
	if err := axfrRes.FromBuffer(arb); err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	if len(axfrRes.Answers) == 0 || axfrRes.Answers[0].Type != packet.SOA {
		t.Errorf("AXFR E2E failed to start with SOA")
	}
	if cerr := tcpConn.Close(); cerr != nil {
		t.Fatalf("Failed to close TCP conn: %v", cerr)
	}

	// 5. Test EDNS(0) + NSEC (Authenticated Denial)
	conn2, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to dial udp: %v", err)
	}
	query2 := packet.NewDNSPacket()
	query2.Questions = append(query2.Questions, packet.DNSQuestion{Name: "missing.advanced.test.", QType: packet.A})
	query2.Resources = append(query2.Resources, packet.DNSRecord{
		Name: ".", Type: packet.OPT, UDPPayloadSize: 4096, Z: 0x8000,
	})
	qBuf2 := packet.NewBytePacketBuffer()
	if err := query2.Write(qBuf2); err != nil {
		t.Fatalf("Failed to write to buffer: %v", err)
	}
	if _, err := conn2.Write(qBuf2.Buf[:qBuf2.Position()]); err != nil {
		t.Fatalf("Failed to write to conn: %v", err)
	}

	n2, err := conn2.Read(resBuf)
	if err != nil {
		t.Fatalf("Failed to read from conn: %v", err)
	}
	res2 := packet.NewDNSPacket()
	pBuf2 := packet.NewBytePacketBuffer()
	pBuf2.Load(resBuf[:n2])
	if err := res2.FromBuffer(pBuf2); err != nil {
		t.Fatalf("Failed to parse packet: %v", err)
	}

	foundNSEC := false
	for _, auth := range res2.Authorities {
		if auth.Type == packet.NSEC {
			foundNSEC = true
			break
		}
	}
	if !foundNSEC {
		t.Errorf("DNSSEC/NSEC E2E failed: no NSEC record in NXDOMAIN response")
	}
	_ = conn2.Close()
}
