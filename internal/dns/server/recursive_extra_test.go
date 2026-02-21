package server

import (
	"net"
	"strings"
	"testing"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestGenerateTransactionID_Randomization(t *testing.T) {
	id1 := generateTransactionID()
	id2 := generateTransactionID()
	
	// While it's mathematically possible to get the same ID twice (1 in 65536),
	// for a unit test we expect them to be different.
	if id1 == id2 {
		t.Errorf("Consecutive IDs should be different (randomized)")
	}
}

func TestSendQuery_IDMismatch(t *testing.T) {
	// 1. Start a mock UDP DNS server that returns WRONG ID
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil { t.Fatalf("ResolveUDPAddr failed: %v", err) }
	
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { t.Fatalf("ListenUDP failed: %v", err) }
	
	go func() {
		defer func() { _ = conn.Close() }() 
		buf := make([]byte, 512)
		_, remote, errRead := conn.ReadFromUDP(buf)
		if errRead != nil { return }
		
		resp := packet.NewDNSPacket()
		resp.Header.ID = 9999 // WRONG ID
		resp.Header.Response = true
		
		resBuf := packet.NewBytePacketBuffer()
		_ = resp.Write(resBuf)
		_, _ = conn.WriteToUDP(resBuf.Buf[:resBuf.Position()], remote)
	}()

	// 2. Call sendQuery
	srv := NewServer(":0", nil, nil)
	serverAddr := conn.LocalAddr().String()
	
	_, err = srv.sendQuery(serverAddr, "query.test.", packet.A)
	if err == nil {
		t.Fatalf("Expected error due to transaction ID mismatch, but got nil")
	}
	
	if !strings.Contains(err.Error(), "transaction ID mismatch") {
		t.Errorf("Expected 'transaction ID mismatch' error, got: %v", err)
	}
}
