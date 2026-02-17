package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func TestExtractRegex(t *testing.T) {
	data := "Throughput:       123.45 queries/sec"
	pattern := `Throughput:\s+([0-9.]+)`
	got := extractRegex(data, pattern)
	if got != "123.45" {
		t.Errorf("Expected 123.45, got %s", got)
	}

	gotNone := extractRegex(data, "missing")
	if gotNone != "N/A" {
		t.Errorf("Expected N/A, got %s", gotNone)
	}
}

func TestPrintEnhancedReport(t *testing.T) {
	stats := &Stats{
		TotalQueries:  10,
		Success:       8,
		Errors:        2,
		BytesSent:     100,
		BytesReceived: 200,
		Latencies:     make(chan time.Duration, 10),
	}
	stats.Latencies <- 10 * time.Millisecond
	stats.Latencies <- 20 * time.Millisecond
	close(stats.Latencies)

	// Verify it doesn't panic
	printEnhancedReport(1*time.Second, stats, 1, 10)
}

func TestRunBenchmark(t *testing.T) {
	// Start a mock UDP server
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer func() { _ = conn.Close() }()
	
	serverAddr := conn.LocalAddr().String()
	
	go func() {
		buf := make([]byte, 512)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil { return }
			
			req := packet.NewDNSPacket()
			pb := packet.NewBytePacketBuffer()
			pb.Load(buf[:n])
			_ = req.FromBuffer(pb)
			
			resp := packet.NewDNSPacket()
			resp.Header.ID = req.Header.ID
			resp.Header.Response = true
			resBuf := packet.NewBytePacketBuffer()
			_ = resp.Write(resBuf)
			_, _ = conn.WriteToUDP(resBuf.Buf[:resBuf.Position()], remote)
		}
	}()

	runBenchmark(serverAddr, 10, 2, 100, 1.1, 100)
}

func TestRunRealisticWorker(t *testing.T) {
	// Start a mock UDP server
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer func() { _ = conn.Close() }()
	
	serverAddr := conn.LocalAddr().String()
	
	go func() {
		buf := make([]byte, 512)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil { return }
			
			req := packet.NewDNSPacket()
			pb := packet.NewBytePacketBuffer()
			pb.Load(buf[:n])
			_ = req.FromBuffer(pb)
			
			resp := packet.NewDNSPacket()
			resp.Header.ID = req.Header.ID
			resp.Header.Response = true
			resBuf := packet.NewBytePacketBuffer()
			_ = resp.Write(resBuf)
			_, _ = conn.WriteToUDP(resBuf.Buf[:resBuf.Position()], remote)
		}
	}()

	stats := &Stats{
		Latencies: make(chan time.Duration, 10),
	}
	runRealisticWorker(serverAddr, 5, 0, 100, 1.1, 100, stats)
	if stats.TotalQueries != 5 {
		t.Errorf("Expected 5 queries, got %d", stats.TotalQueries)
	}
}

func TestSeedDatabase(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil { t.Fatalf("failed to open sqlmock: %s", err) }
	defer func() { _ = db.Close() }()

	mock.ExpectExec("INSERT INTO dns_zones").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO dns_records").WillReturnResult(sqlmock.NewResult(1, 1))

	err = seedDatabase(context.Background(), db, 10)
	if err != nil {
		t.Errorf("seedDatabase failed: %v", err)
	}
}

func TestRunRealisticWorker_ConnError(t *testing.T) {
	stats := &Stats{}
	// Use an unreachable port
	runRealisticWorker("127.0.0.1:1", 1, 0, 100, 1.1, 100, stats)
	// Should just return silently after printing error
}

func TestRunSeed_InvalidDB(t *testing.T) {
	// Should not panic, just print error
	runSeed(10) 
}
