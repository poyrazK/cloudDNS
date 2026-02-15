package server

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestDoH_E2E(t *testing.T) {
	repo := &mockServerRepo{
		records: []domain.Record{
			{Name: "doh-e2e.test.", Type: domain.TypeA, Content: "9.9.9.9", TTL: 60},
		},
	}
	srv := NewServer("127.0.0.1:0", repo, nil)

	// Create a test server using the DoH handler
	ts := httptest.NewServer(http.HandlerFunc(srv.handleDoH))
	defer ts.Close()

	// 1. Valid Query (POST)
	req := packet.NewDnsPacket()
	req.Header.ID = 1234
	req.Questions = append(req.Questions, packet.DnsQuestion{Name: "doh-e2e.test.", QType: packet.A})
	reqBuf := packet.NewBytePacketBuffer()
	req.Write(reqBuf)
	reqData := reqBuf.Buf[:reqBuf.Position()]

	resp, err := http.Post(ts.URL+"/dns-query", "application/dns-message", bytes.NewReader(reqData))
	if err != nil {
		t.Fatalf("DoH POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/dns-message" {
		t.Errorf("Expected Content-Type application/dns-message, got %s", resp.Header.Get("Content-Type"))
	}

	resBody, _ := io.ReadAll(resp.Body)
	resPacket := packet.NewDnsPacket()
	resBuf := packet.NewBytePacketBuffer()
	resBuf.Load(resBody)
	if err := resPacket.FromBuffer(resBuf); err != nil {
		t.Fatalf("Failed to parse DoH response: %v", err)
	}

	if len(resPacket.Answers) != 1 || resPacket.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("DoH response mismatch: %+v", resPacket.Answers)
	}

	// 2. Valid Query (GET)
	b64Query := base64.RawURLEncoding.EncodeToString(reqData)
	respGET, err := http.Get(ts.URL + "/dns-query?dns=" + b64Query)
	if err != nil {
		t.Fatalf("DoH GET failed: %v", err)
	}
	defer respGET.Body.Close()

	if respGET.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for GET, got %d", respGET.StatusCode)
	}
	
	resBody, _ = io.ReadAll(respGET.Body)
	resPacket = packet.NewDnsPacket()
	resBuf = packet.NewBytePacketBuffer()
	resBuf.Load(resBody)
	resPacket.FromBuffer(resBuf)
	if len(resPacket.Answers) != 1 || resPacket.Answers[0].IP.String() != "9.9.9.9" {
		t.Errorf("DoH GET response mismatch")
	}

	// 3. Invalid Content-Type (POST)
	respInv, err := http.Post(ts.URL+"/dns-query", "text/plain", bytes.NewReader(reqData))
	if err == nil { respInv.Body.Close() }
	if respInv != nil && respInv.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid content-type, got %d", respInv.StatusCode)
	}

	// 4. Invalid Method
	reqReq, _ := http.NewRequest("PUT", ts.URL+"/dns-query", nil)
	respMeth, err := http.DefaultClient.Do(reqReq)
	if err == nil { respMeth.Body.Close() }
	if respMeth != nil && respMeth.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed for PUT, got %d", respMeth.StatusCode)
	}

	// 5. Missing 'dns' parameter (GET)
	respMiss, err := http.Get(ts.URL + "/dns-query")
	if err == nil { respMiss.Body.Close() }
	if respMiss != nil && respMiss.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for missing dns param, got %d", respMiss.StatusCode)
	}

	// 6. Invalid base64 (GET)
	respB64, err := http.Get(ts.URL + "/dns-query?dns=!!!")
	if err == nil { respB64.Body.Close() }
	if respB64 != nil && respB64.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid base64, got %d", respB64.StatusCode)
	}
}
