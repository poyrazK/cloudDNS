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

// TestEndToEndDNSSEC_Lifecycle verifies the full automated DNSSEC flow:
// 1. Zone creation via API
// 2. Automatic KSK/ZSK key generation
// 3. Dynamic RRSIG signing of query responses when DO bit is set
func TestEndToEndDNSSEC_Lifecycle(t *testing.T) {
	// 1. Setup Stack
	repo := &mockServerRepo{}
	dnsSvc := services.NewDNSService(repo)
	dnsAddr := "127.0.0.1:10057"
	apiAddr := "127.0.0.1:18082"

	dnsSrv := NewServer(dnsAddr, repo, nil)
	_ = dnsSrv.Run()

	apiHandler := api.NewAPIHandler(dnsSvc)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)
	apiSrv := &http.Server{Addr: apiAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	_ = apiSrv.ListenAndServe()

	// Wait for servers to start
	time.Sleep(200 * time.Millisecond)
	_ = apiSrv.Shutdown(context.Background())

	// 2. Create a new zone via API
	zoneReq := domain.Zone{Name: "dnssec.e2e.", TenantID: "admin"}
	body, _ := json.Marshal(zoneReq)
	resp, err := http.Post(fmt.Sprintf("http://%s/zones", apiAddr), "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create zone via API: %v", err)
	}
	_ = resp.Body.Close()
	var createdZone domain.Zone
	_ = json.NewDecoder(resp.Body).Decode(&createdZone)

	// Add an A record to the zone
	record := domain.Record{
		Name:    "www.dnssec.e2e.",
		Type:    domain.TypeA,
		Content: "1.2.3.4",
		TTL:     300,
		ZoneID:  createdZone.ID,
	}
	rb, _ := json.Marshal(record)
	_, _ = http.Post(fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID), "application/json", bytes.NewBuffer(rb))

	// 3. Trigger DNSSEC Automation
	// Force the lifecycle management to generate keys for the new zone
	err = dnsSrv.DNSSEC.AutomateLifecycle(context.Background(), createdZone.ID)
	if err != nil {
		t.Fatalf("DNSSEC automation failed: %v", err)
	}

	// 4. Verify keys were generated in the repo
	keys, _ := repo.ListKeysForZone(context.Background(), createdZone.ID)
	hasKSK := false
	hasZSK := false
	for _, k := range keys {
		if k.KeyType == "KSK" { hasKSK = true }
		if k.KeyType == "ZSK" { hasZSK = true }
	}
	if !hasKSK || !hasZSK {
		t.Errorf("DNSSEC automation failed to generate KSK/ZSK pairs")
	}

	// 5. Query with DO bit and verify dynamic signing (RRSIG)
	query := packet.NewDNSPacket()
	query.Header.ID = 0xABCD
	query.Questions = append(query.Questions, packet.DNSQuestion{Name: "www.dnssec.e2e.", QType: packet.A})
	
	// Add OPT record with DO bit (DNSSEC OK)
	query.Resources = append(query.Resources, packet.DNSRecord{
		Name:           ".",
		Type:           packet.OPT,
		UDPPayloadSize: 4096,
		Z:              0x8000, // DO bit set
	})
	
	qBuf := packet.NewBytePacketBuffer()
	_ = query.Write(qBuf)

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS server: %v", err)
	}
	_ = conn.Close()
	
	_, _ = conn.Write(qBuf.Buf[:qBuf.Position()])
	
	resBuf := make([]byte, 2048)
	n, err := conn.Read(resBuf)
	if err != nil {
		t.Fatalf("Failed to read from DNS server: %v", err)
	}
	
	res := packet.NewDNSPacket()
	pBuf := packet.NewBytePacketBuffer()
	copy(pBuf.Buf, resBuf[:n])
	_ = res.FromBuffer(pBuf)

	// Verify Answer section has the A record AND its corresponding RRSIG
	foundA := false
	foundRRSIG := false
	for _, ans := range res.Answers {
		if ans.Type == packet.A { foundA = true }
		if ans.Type == packet.RRSIG { foundRRSIG = true }
	}

	if !foundA {
		t.Errorf("Expected A record in answer, not found")
	}
	if !foundRRSIG {
		t.Errorf("DNSSEC E2E failed: No RRSIG record in answer section despite DO bit being set")
	}

	// 6. Test signed NXDOMAIN (Authenticated Denial)
	query2 := packet.NewDNSPacket()
	query2.Questions = append(query2.Questions, packet.DNSQuestion{Name: "nonexistent.dnssec.e2e.", QType: packet.A})
	query2.Resources = append(query2.Resources, packet.DNSRecord{
		Name: ".", Type: packet.OPT, UDPPayloadSize: 4096, Z: 0x8000,
	})
	
	qBuf2 := packet.NewBytePacketBuffer()
	_ = query2.Write(qBuf2)
	_, _ = conn.Write(qBuf2.Buf[:qBuf2.Position()])
	
	n2, _ := conn.Read(resBuf)
	res2 := packet.NewDNSPacket()
	pBuf2 := packet.NewBytePacketBuffer()
	copy(pBuf2.Buf, resBuf[:n2])
	_ = res2.FromBuffer(pBuf2)

	if res2.Header.ResCode != 3 {
		t.Errorf("Expected NXDOMAIN, got %d", res2.Header.ResCode)
	}

	foundNSEC := false
	foundNSEC_RRSIG := false
	for _, auth := range res2.Authorities {
		if auth.Type == packet.NSEC { foundNSEC = true }
		if auth.Type == packet.RRSIG && auth.TypeCovered == uint16(packet.NSEC) {
			foundNSEC_RRSIG = true
		}
	}

	if !foundNSEC {
		t.Errorf("NXDOMAIN response missing NSEC record")
	}
	if !foundNSEC_RRSIG {
		t.Errorf("NSEC record in NXDOMAIN response is not signed (missing RRSIG)")
	}
}
