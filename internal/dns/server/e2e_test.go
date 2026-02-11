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

func TestEndToEndDNS(t *testing.T) {
	// 1. Setup Stack with Mock Repo
	repo := &mockServerRepo{} // Using the mock from server_test.go
	svc := services.NewDNSService(repo)
	dnsAddr := "127.0.0.1:10055"
	apiAddr := "127.0.0.1:18080"

	// 2. Start DNS Server
	dnsSrv := NewServer(dnsAddr, repo, nil)
	go dnsSrv.Run()

	// 3. Start Management API
	apiHandler := api.NewAPIHandler(svc)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)
	apiSrv := &http.Server{Addr: apiAddr, Handler: mux}
	go apiSrv.ListenAndServe()

	// Give servers a moment to start
	time.Sleep(200 * time.Millisecond)
	defer apiSrv.Shutdown(context.Background())

	// 4. Create a Zone via API
	zoneReq := domain.Zone{
		Name:     "e2e.test",
		TenantID: "admin",
	}
	body, _ := json.Marshal(zoneReq)
	resp, err := http.Post(fmt.Sprintf("http://%s/zones", apiAddr), "application/json", bytes.NewBuffer(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create zone via API: %v", err)
	}
	var createdZone domain.Zone
	json.NewDecoder(resp.Body).Decode(&createdZone)

	// 5. Create a Record via API
	recordReq := domain.Record{
		Name:    "www.e2e.test",
		Type:    domain.TypeA,
		Content: "9.9.9.9",
		TTL:     300,
	}
	body, _ = json.Marshal(recordReq)
	url := fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID)
	resp, err = http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Failed to create record via API: %v", err)
	}

	// 6. Query via DNS (UDP)
	// Manually construct and send a UDP packet to our server
	query := packet.NewDnsPacket()
	query.Header.ID = 0xbeef
	query.Questions = append(query.Questions, packet.DnsQuestion{
		Name: "www.e2e.test", QType: packet.A,
	})
	qBuf := packet.NewBytePacketBuffer()
	query.Write(qBuf)

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(qBuf.Buf[:qBuf.Position()])
	if err != nil {
		t.Fatalf("Failed to send DNS query: %v", err)
	}

	resBuf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(resBuf)
	if err != nil {
		t.Fatalf("Failed to read DNS response: %v", err)
	}

	// 7. Verify Result
	resPacket := packet.NewDnsPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, resBuf[:n])
	err = resPacket.FromBuffer(pBuf)
	if err != nil {
		t.Fatalf("Failed to parse DNS response: %v", err)
	}

	if len(resPacket.Answers) == 0 {
		t.Fatal("Expected at least one answer in DNS response")
	}
	if resPacket.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("Expected IP 9.9.9.9, got %s", resPacket.Answers[0].IP.String())
	}

	// 8. Query via DNS (TCP)
	tcpConn, err := net.Dial("tcp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS via TCP: %v", err)
	}
	defer tcpConn.Close()

	// Prepend 2-byte length for TCP
	tcpQBuf := make([]byte, qBuf.Position()+2)
	tcpQBuf[0] = byte(qBuf.Position() >> 8)
	tcpQBuf[1] = byte(qBuf.Position() & 0xFF)
	copy(tcpQBuf[2:], qBuf.Buf[:qBuf.Position()])

	_, err = tcpConn.Write(tcpQBuf)
	if err != nil {
		t.Fatalf("Failed to send DNS query via TCP: %v", err)
	}

	// Read length
	tcpLenBuf := make([]byte, 2)
	tcpConn.Read(tcpLenBuf)
	tcpRespLen := uint16(tcpLenBuf[0])<<8 | uint16(tcpLenBuf[1])

	tcpResBuf := make([]byte, tcpRespLen)
	_, err = tcpConn.Read(tcpResBuf)
	if err != nil {
		t.Fatalf("Failed to read DNS response via TCP: %v", err)
	}

	resPacketTCP := packet.NewDnsPacket()
	pBufTCP := packet.NewBytePacketBuffer()
	copy(pBufTCP.Buf, tcpResBuf)
	resPacketTCP.FromBuffer(pBufTCP)

	if len(resPacketTCP.Answers) == 0 || resPacketTCP.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("TCP resolution failed")
	}
}
