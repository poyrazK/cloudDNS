package server

import (
	"bytes"
	"context"
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

func TestEndToEndDNS_Advanced(t *testing.T) {
	// 1. Setup Stack with Mock Repo (or real PG if we wanted even more integration)
	repo := &mockServerRepo{}
	svc := services.NewDNSService(repo, nil)
	dnsAddr := "127.0.0.1:10056"
	apiAddr := "127.0.0.1:18081"

	dnsSrv := NewServer(dnsAddr, repo, nil)
	go func() {
		_ = dnsSrv.Run()
	}()

	apiHandler := api.NewAPIHandler(svc)
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

	// 2. Setup Zone with multiple records including Wildcards
	zoneReq := domain.Zone{Name: "advanced.test.", TenantID: "admin"}
	body, _ := json.Marshal(zoneReq)
	resp, err := http.Post(fmt.Sprintf("http://%s/zones", apiAddr), "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create zone: %v", err)
	}
	var createdZone domain.Zone
	_ = json.NewDecoder(resp.Body).Decode(&createdZone)
	_ = resp.Body.Close()

	records := []domain.Record{
		{Name: "a.advanced.test.", Type: domain.TypeA, Content: "1.1.1.1", TTL: 300, ZoneID: createdZone.ID},
		{Name: "*.advanced.test.", Type: domain.TypeTXT, Content: "wildcard", TTL: 300, ZoneID: createdZone.ID},
	}
	for _, r := range records {
		b, _ := json.Marshal(r)
		if resp2, err2 := http.Post(fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID), "application/json", bytes.NewBuffer(b)); err2 == nil { _ = resp2.Body.Close() }
	}

	// 3. Test Wildcard Resolution
	query := packet.NewDNSPacket()
	query.Questions = append(query.Questions, packet.DNSQuestion{Name: "anything.advanced.test.", QType: packet.TXT})
	qBuf := packet.NewBytePacketBuffer()
	_ = query.Write(qBuf)

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS: %v", err)
	}
	_, _ = conn.Write(qBuf.Buf[:qBuf.Position()])
	resBuf := make([]byte, 1024)
	n, _ := conn.Read(resBuf)
	
	res := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, resBuf[:n])
	_ = res.FromBuffer(pBuf)

	if len(res.Answers) == 0 || res.Answers[0].Txt != "wildcard" {
		t.Errorf("Wildcard E2E failed")
	}
	_ = conn.Close()

	// 4. Test AXFR over TCP
	tcpConn, err := net.Dial("tcp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS TCP: %v", err)
	}
	axfrQuery := packet.NewDNSPacket()
	axfrQuery.Header.ID = 0x1234
	axfrQuery.Questions = append(axfrQuery.Questions, packet.DNSQuestion{Name: "advanced.test.", QType: packet.AXFR})
	aqBuf := packet.NewBytePacketBuffer()
	_ = axfrQuery.Write(aqBuf)

	data := aqBuf.Buf[:aqBuf.Position()]
	fullData := append([]byte{byte(len(data) >> 8), byte(len(data) & 0xFF)}, data...)
	_, _ = tcpConn.Write(fullData)

	// Read first SOA
	lenB := make([]byte, 2)
	_, _ = tcpConn.Read(lenB)
	axfrRLen := uint16(lenB[0])<<8 | uint16(lenB[1])
	axfrRData := make([]byte, axfrRLen)
	_, _ = tcpConn.Read(axfrRData)
	
	axfrRes := packet.NewDNSPacket()
	arb := packet.NewBytePacketBuffer()
	copy(arb.Buf, axfrRData)
	_ = axfrRes.FromBuffer(arb)
	
	if len(axfrRes.Answers) == 0 || axfrRes.Answers[0].Type != packet.SOA {
		t.Errorf("AXFR E2E failed to start with SOA")
	}
	_ = tcpConn.Close()

	// 5. Test EDNS(0) + NSEC (Authenticated Denial)
	conn2, _ := net.Dial("udp", dnsAddr)
	query2 := packet.NewDNSPacket()
	query2.Questions = append(query2.Questions, packet.DNSQuestion{Name: "missing.advanced.test.", QType: packet.A})
	query2.Resources = append(query2.Resources, packet.DNSRecord{
		Name: ".", Type: packet.OPT, UDPPayloadSize: 4096, Z: 0x8000,
	})
	qBuf2 := packet.NewBytePacketBuffer()
	_ = query2.Write(qBuf2)
	_, _ = conn2.Write(qBuf2.Buf[:qBuf2.Position()])
	
	n2, _ := conn2.Read(resBuf)
	res2 := packet.NewDNSPacket()
	pBuf2 := packet.NewBytePacketBuffer()
	copy(pBuf2.Buf, resBuf[:n2])
	_ = res2.FromBuffer(pBuf2)

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
