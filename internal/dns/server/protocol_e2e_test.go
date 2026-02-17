package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/poyrazK/cloudDNS/internal/adapters/api"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/core/services"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

// TestEndToEnd_RFC_Extensions verifies the combined flow of:
// 1. Creating a zone via Management API
// 2. Performing an authenticated Dynamic Update (RFC 2136) via DNS port
// 3. Verifying the update results in a DNS NOTIFY (RFC 1996) to a slave
// 4. Performing an Incremental Zone Transfer (IXFR - RFC 1995) to retrieve the changes
func TestEndToEnd_RFC_Extensions(t *testing.T) {
	// 1. Setup Stack
	repo := &mockServerRepo{}
	dnsSvc := services.NewDNSService(repo)
	dnsAddr := "127.0.0.1:10058"
	apiAddr := "127.0.0.1:18083"
	slaveAddr := "127.0.0.1:10059"

	dnsSrv := NewServer(dnsAddr, repo, nil)
	dnsSrv.TsigKeys["admin-key."] = []byte("secret123")
	dnsSrv.NotifyPortOverride = 10059
	go dnsSrv.Run()

	apiHandler := api.NewAPIHandler(dnsSvc)
	mux := http.NewServeMux()
	apiHandler.RegisterRoutes(mux)
	apiSrv := &http.Server{Addr: apiAddr, Handler: mux}
	go apiSrv.ListenAndServe()

	// Setup a mock "slave" to receive NOTIFY
	notifyReceived := make(chan *packet.DNSPacket, 1)
	slaveConn, err := net.ListenPacket("udp", slaveAddr)
	if err != nil { t.Fatalf("Failed to listen on slave addr: %v", err) }
	defer slaveConn.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, err := slaveConn.ReadFrom(buf)
			if err != nil { return }
			p := packet.NewDNSPacket()
			pb := packet.NewBytePacketBuffer()
			pb.Load(buf[:n])
			if err := p.FromBuffer(pb); err == nil {
				if p.Header.Opcode == packet.OPCODE_NOTIFY {
					notifyReceived <- p
					return
				}
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	defer apiSrv.Shutdown(context.Background())

	// 2. Create Zone via API with the slave listed in NS records
	zoneReq := domain.Zone{Name: "rfc.test.", TenantID: "admin"}
	body, _ := json.Marshal(zoneReq)
	resp, err := http.Post(fmt.Sprintf("http://%s/zones", apiAddr), "application/json", bytes.NewBuffer(body))
	if err != nil { t.Fatalf("POST /zones failed: %v", err) }
	defer resp.Body.Close()
	var createdZone domain.Zone
	if err := json.NewDecoder(resp.Body).Decode(&createdZone); err != nil {
		t.Fatalf("Failed to decode created zone: %v", err)
	}
	if createdZone.ID == "" { t.Fatalf("Created zone ID is empty") }

	// Add an NS record pointing to our mock slave IP
	nsRec := domain.Record{
		Name: "rfc.test.", Type: domain.TypeNS, Content: "ns-slave.rfc.test.", ZoneID: createdZone.ID,
	}
	nb, _ := json.Marshal(nsRec)
	respNS, err := http.Post(fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID), "application/json", bytes.NewBuffer(nb))
	if err == nil { respNS.Body.Close() }
	
	// Add Glue record for the slave NS so notifySlaves can resolve it
	glueRec := domain.Record{
		Name: "ns-slave.rfc.test.", Type: domain.TypeA, Content: "127.0.0.1", ZoneID: createdZone.ID,
	}
	gb, _ := json.Marshal(glueRec)
	respGlue, err := http.Post(fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID), "application/json", bytes.NewBuffer(gb))
	if err == nil { respGlue.Body.Close() }

	// Get the starting serial
	recs, _ := repo.GetRecords(context.Background(), "rfc.test.", domain.TypeSOA, "")
	if len(recs) == 0 { t.Fatalf("SOA record not found in repo") }
	var startSerial uint32
	fmt.Sscanf(strings.Fields(recs[0].Content)[2], "%d", &startSerial)

	// 3. Perform Authenticated Dynamic Update via DNS
	update := packet.NewDNSPacket()
	update.Header.Opcode = packet.OPCODE_UPDATE
	update.Questions = append(update.Questions, packet.DNSQuestion{Name: "rfc.test.", QType: packet.SOA})
	update.Authorities = append(update.Authorities, packet.DNSRecord{
		Name: "dynamic.rfc.test.", Type: packet.A, Class: 1, TTL: 300, IP: net.ParseIP("5.5.5.5"),
	})
	
	uBuf := packet.NewBytePacketBuffer()
	update.Write(uBuf)
	err = update.SignTSIG(uBuf, "admin-key.", []byte("secret123"))
	if err != nil { t.Fatalf("TSIG sign failed: %v", err) }

	dnsConn, err := net.Dial("udp", dnsAddr)
	if err != nil { t.Fatalf("Dial DNS failed: %v", err) }
	dnsConn.Write(uBuf.Buf[:uBuf.Position()])
	
	resBuf := make([]byte, 1024)
	dnsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := dnsConn.Read(resBuf)
	if err != nil { t.Fatalf("Read DNS response failed: %v", err) }
	
	resUpdate := packet.NewDNSPacket()
	resPb := packet.NewBytePacketBuffer()
	resPb.Load(resBuf[:n])
	resUpdate.FromBuffer(resPb)
	if resUpdate.Header.ResCode != 0 {
		t.Errorf("Dynamic Update failed with RCODE %d", resUpdate.Header.ResCode)
	}

	// 4. Verify NOTIFY was received by the slave
	select {
	case p := <-notifyReceived:
		if p.Header.Opcode != packet.OPCODE_NOTIFY {
			t.Errorf("Expected NOTIFY packet, got opcode %d", p.Header.Opcode)
		}
		if p.Questions[0].Name != "rfc.test." {
			t.Errorf("NOTIFY zone mismatch: %s", p.Questions[0].Name)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("Timed out waiting for DNS NOTIFY")
	}

	// 5. Verify change via API
	respRecs, err := http.Get(fmt.Sprintf("http://%s/zones/%s/records?tenant_id=admin", apiAddr, createdZone.ID))
	if err != nil { t.Fatalf("GET records failed: %v", err) }
	defer respRecs.Body.Close()
	var zoneRecs []domain.Record
	json.NewDecoder(respRecs.Body).Decode(&zoneRecs)
	foundDynamic := false
	for _, r := range zoneRecs {
		if r.Name == "dynamic.rfc.test." { foundDynamic = true }
	}
	if !foundDynamic { 
		// Dump all records for debugging
		all, _ := repo.ListRecordsForZone(context.Background(), createdZone.ID)
		t.Errorf("Dynamic record not found via API after update. API records: %v. Repo records: %v", zoneRecs, all) 
	}

	// 6. Perform IXFR over TCP
	tcpConn, err := net.Dial("tcp", dnsAddr)
	if err != nil { t.Fatalf("Dial TCP DNS failed: %v", err) }
	defer tcpConn.Close()
	
	ixfr := packet.NewDNSPacket()
	ixfr.Questions = append(ixfr.Questions, packet.DNSQuestion{Name: "rfc.test.", QType: packet.IXFR})
	// Current SOA in Authority section
	ixfr.Authorities = append(ixfr.Authorities, packet.DNSRecord{
		Name: "rfc.test.", Type: packet.SOA, Serial: startSerial,
	})
	
	ixBuf := packet.NewBytePacketBuffer()
	ixfr.Write(ixBuf)
	
	tcpIxBuf := make([]byte, ixBuf.Position()+2)
	tcpIxBuf[0] = byte(ixBuf.Position() >> 8)
	tcpIxBuf[1] = byte(ixBuf.Position() & 0xFF)
	copy(tcpIxBuf[2:], ixBuf.Buf[:ixBuf.Position()])
	tcpConn.Write(tcpIxBuf)

	lenB := make([]byte, 2)
	tcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(tcpConn, lenB)
	if err != nil { t.Fatalf("Read IXFR len failed: %v", err) }
	
	ixfrRLen := uint16(lenB[0])<<8 | uint16(lenB[1])
	ixfrRData := make([]byte, ixfrRLen)
	_, err = io.ReadFull(tcpConn, ixfrRData)
	if err != nil { t.Fatalf("Read IXFR data failed: %v", err) }
	
	resIXFR := packet.NewDNSPacket()
	ixPb := packet.NewBytePacketBuffer()
	ixPb.Load(ixfrRData)
	resIXFR.FromBuffer(ixPb)
	if len(resIXFR.Answers) == 0 || resIXFR.Answers[0].Type != packet.SOA {
		t.Errorf("IXFR failed to start with SOA. Answers: %v", resIXFR.Answers)
	}
	if len(resIXFR.Answers) > 0 && resIXFR.Answers[0].Serial != startSerial+1 {
		t.Errorf("IXFR SOA serial mismatch: expected %d, got %d", startSerial+1, resIXFR.Answers[0].Serial)
	}
}
