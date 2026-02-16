package server

import (
	"bytes"
	"context"
	"crypto/tls"
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

func TestEndToEnd_Protocols(t *testing.T) {
	// 1. Setup Stack
	repo := &mockServerRepo{}
	svc := services.NewDNSService(repo)
	dnsAddr := "127.0.0.1:10058"
	apiAddr := "127.0.0.1:18083"

	dnsSrv := NewServer(dnsAddr, repo, nil)
	// Mock TLS for DoT/DoH testing
	cert, _ := tls.X509KeyPair([]byte(""), []byte("")) // Mock won't actually work without real certs, but we test the setup
	dnsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	
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

	time.Sleep(500 * time.Millisecond)
	defer func() {
		_ = apiSrv.Shutdown(context.Background())
	}()

	// 2. Setup Zone
	zoneReq := domain.Zone{Name: "protocols.test.", TenantID: "admin"}
	bz, _ := json.Marshal(zoneReq)
	resp, err := http.Post(fmt.Sprintf("http://%s/zones", apiAddr), "application/json", bytes.NewBuffer(bz))
	if err != nil {
		t.Fatalf("Failed to create zone: %v", err)
	}
	var createdZone domain.Zone
	_ = json.NewDecoder(resp.Body).Decode(&createdZone)
	_ = resp.Body.Close()

	rec := domain.Record{Name: "www.protocols.test.", Type: domain.TypeA, Content: "1.2.3.4", TTL: 60, ZoneID: createdZone.ID}
	br, _ := json.Marshal(rec)
	_, _ = http.Post(fmt.Sprintf("http://%s/zones/%s/records", apiAddr, createdZone.ID), "application/json", bytes.NewBuffer(br))

	// 3. Test UDP
	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS: %v", err)
	}
	q := packet.NewDNSPacket()
	q.Questions = append(q.Questions, packet.DNSQuestion{Name: "www.protocols.test.", QType: packet.A})
	qb := packet.NewBytePacketBuffer()
	_ = q.Write(qb)
	_, _ = conn.Write(qb.Buf[:qb.Position()])
	
	rb := make([]byte, 1024)
	n, _ := conn.Read(rb)
	res := packet.NewDNSPacket()
	pb := packet.NewBytePacketBuffer()
	copy(pb.Buf, rb[:n])
	_ = res.FromBuffer(pb)
	if len(res.Answers) == 0 || res.Answers[0].IP.String() != "1.2.3.4" {
		t.Errorf("UDP E2E failed")
	}
	_ = conn.Close()

	// 4. Test TCP
	tConn, err := net.Dial("tcp", dnsAddr)
	if err != nil {
		t.Fatalf("Failed to connect to DNS TCP: %v", err)
	}
	tqb := packet.NewBytePacketBuffer()
	_ = q.Write(tqb)
	data := tqb.Buf[:tqb.Position()]
	fullData := append([]byte{byte(len(data) >> 8), byte(len(data) & 0xFF)}, data...)
	_, _ = tConn.Write(fullData)
	
	lenB := make([]byte, 2)
	_, _ = tConn.Read(lenB)
	rlen := uint16(lenB[0])<<8 | uint16(lenB[1])
	rdata := make([]byte, rlen)
	_, _ = tConn.Read(rdata)
	
	res2 := packet.NewDNSPacket()
	pb2 := packet.NewBytePacketBuffer()
	copy(pb2.Buf, rdata)
	_ = res2.FromBuffer(pb2)
	if len(res2.Answers) == 0 || res2.Answers[0].IP.String() != "1.2.3.4" {
		t.Errorf("TCP E2E failed")
	}
	_ = tConn.Close()
}
