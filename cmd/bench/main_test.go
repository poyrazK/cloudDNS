package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
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

func TestPrintEnhancedReport(_ *testing.T) {
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

func TestRunBenchmark(_ *testing.T) {
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

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestRunRealisticWorker_ConnError(_ *testing.T) {
	stats := &Stats{}
	// Use an unreachable port
	runRealisticWorker("127.0.0.1:1", 1, 0, 100, 1.1, 100, stats)
}

func TestRunSeed_InvalidDB(t *testing.T) {
	// Should not panic, just print error
	runSeed(10) 
}

func TestRunSeed_Errors(t *testing.T) {
	t.Run("ConnectionError", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "invalid-url")
		// Should print error and return
		runSeed(1)
	})
}

func TestMain_Bench(_ *testing.T) {
	// Reset flags for testing
	oldCommandLine := flag.CommandLine
	defer func() { flag.CommandLine = oldCommandLine }()
	flag.CommandLine = flag.NewFlagSet("bench", flag.ExitOnError)
	
	// Start a mock UDP server to avoid hang
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:10053")
	conn, err := net.ListenUDP("udp", addr)
	if err == nil {
		defer func() { _ = conn.Close() }()
		go func() {
			buf := make([]byte, 512)
			_, remote, _ := conn.ReadFromUDP(buf)
			_, _ = conn.WriteToUDP([]byte{0,0,0,0}, remote)
		}()
	}

	// We call run instead of main to avoid os.Exit
	runBenchmark("127.0.0.1:10053", 1, 1, 1, 1.1, 1)
}

func TestMain_ScaleMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy scale test in short mode")
	}
}

func TestMain_SeedMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy seed test in short mode")
	}
}

func TestRunAndCaptureScale_Parsing(t *testing.T) {
	// Deterministic parser test
	sampleOutput := "Throughput:       500.00 queries/sec\nP50 (Median):     1.2ms\nP99:              5.5ms\nReliability:      100.00%"
	
	tp := extractRegex(sampleOutput, `Throughput:\s+([0-9.]+)`)
	if tp != "500.00" {
		t.Errorf("Expected 500.00, got %s", tp)
	}
	
	p50 := extractRegex(sampleOutput, `P50 \(Median\):\s+([0-9a-z.]+)`)
	if p50 != "1.2ms" {
		t.Errorf("Expected 1.2ms, got %s", p50)
	}
}

func TestRunSeed_Direct(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid")
	runSeed(1)
}

func TestRunScaleTest_Direct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy scale test in short mode")
	}
	// Just hit the entry point
	defer func() { _ = recover() }()
	runScaleTest(1, 1)
}

func TestRunScaleTest_Errors(t *testing.T) {
	// These tests use environment variables to trigger early returns in runScaleTest
	
	t.Run("InvalidDB", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "invalid-url")
		// Should print error and return
		runScaleTest(1, 1)
	})
}

func TestRun_Comprehensive(t *testing.T) {
	// Test the dispatcher with various modes
	
	// 1. Benchmark mode (default)
	t.Run("BenchmarkMode", func(t *testing.T) {
		// Mock server for the benchmark to talk to
		addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		conn, _ := net.ListenUDP("udp", addr)
		defer conn.Close()
		serverAddr := conn.LocalAddr().String()

		args := []string{"bench", "-server", serverAddr, "-n", "1", "-c", "1"}
		if err := Run(args); err != nil {
			t.Errorf("Run (benchmark) failed: %v", err)
		}
	})

	// 2. Help/Invalid flag
	t.Run("InvalidFlag", func(t *testing.T) {
		args := []string{"bench", "-invalid-flag"}
		if err := Run(args); err == nil {
			t.Error("Expected error for invalid flag")
		}
	})

	// 3. Seed mode (short circuit)
	t.Run("SeedMode", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "none")
		args := []string{"bench", "-mode", "seed", "-range", "1"}
		if err := Run(args); err != nil {
			t.Errorf("Run (seed) failed: %v", err)
		}
	})

	// 4. Scale test mode (short circuit)
	t.Run("ScaleTestMode", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "none")
		args := []string{"bench", "-mode", "scale-test", "-n", "1"}
		if err := Run(args); err != nil {
			t.Errorf("Run (scale-test) failed: %v", err)
		}
	})
}

func TestSeedDatabase_Errors(t *testing.T) {
	t.Run("ZoneInsertError", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil { t.Fatalf("failed to open sqlmock: %s", err) }
		defer db.Close()

		mock.ExpectExec("INSERT INTO dns_zones").WillReturnError(errors.New("insert fail"))
		err = seedDatabase(context.Background(), db, 1)
		if err == nil { t.Error("expected error") }
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})

	t.Run("RecordInsertError", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil { t.Fatalf("failed to open sqlmock: %s", err) }
		defer db.Close()

		mock.ExpectExec("INSERT INTO dns_zones").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO dns_records").WillReturnError(errors.New("insert fail"))
		err = seedDatabase(context.Background(), db, 1)
		if err == nil { t.Error("expected error") }
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unmet expectations: %v", err)
		}
	})
}

func TestRunSeed_ConnectionError(t *testing.T) {
	// Force a connection error in runSeed by using a bad DSN
	t.Setenv("DATABASE_URL", "host=/invalid/path/socket")
	runSeed(1)
}

func TestRunSeed_DefaultURL(t *testing.T) {
	// Test when DATABASE_URL is not set (uses default)
	os.Unsetenv("DATABASE_URL")
	// This will try to connect to localhost with default credentials
	// We expect it to fail with connection error since there's no local DB
	runSeed(1)
}

func TestRunScaleTest_MoreErrors(t *testing.T) {
	t.Run("BadDSN", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "host=/invalid/path/socket")
		runScaleTest(1, 1)
	})
}

// TestRunRealisticWorker_WriteError tests write error path
func TestRunRealisticWorker_WriteError(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	conn.Close() // Close before worker uses it

	stats := &Stats{
		Latencies: make(chan time.Duration, 10),
	}
	runRealisticWorker(conn.LocalAddr().String(), 1, 0, 100, 1.1, 100, stats)
}

// TestRunRealisticWorker_ReadError tests read timeout error path
func TestRunRealisticWorker_ReadError(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Goroutine that accepts but never responds
	go func() {
		buf := make([]byte, 512)
		_, _, _ = conn.ReadFromUDP(buf)
	}()

	stats := &Stats{
		Latencies: make(chan time.Duration, 10),
	}
	// With very short timeout, read should error
	runRealisticWorker(serverAddr, 1, 0, 100, 1.1, 1, stats)
	// Expect errors to be incremented
}

// TestRunRealisticWorker_SuccessfulQuery tests a successful query path
func TestRunRealisticWorker_SuccessfulQuery(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Goroutine that responds
	go func() {
		buf := make([]byte, 512)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

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
	runRealisticWorker(serverAddr, 3, 0, 100, 1.1, 100, stats)

	if stats.TotalQueries != 3 {
		t.Errorf("Expected 3 queries, got %d", stats.TotalQueries)
	}
}

// TestSeedDatabase_SmallTotal tests when total < batchSize (5000)
func TestSeedDatabase_SmallTotal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO dns_zones").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO dns_records").WillReturnResult(sqlmock.NewResult(1, 1))

	err = seedDatabase(context.Background(), db, 100) // Less than batchSize (5000)
	if err != nil {
		t.Errorf("seedDatabase failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSeedDatabase_EmptyEarlyReturn tests when total=0
func TestSeedDatabase_ZeroTotal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %s", err)
	}
	defer db.Close()

	mock.ExpectExec("INSERT INTO dns_zones").WillReturnResult(sqlmock.NewResult(1, 1))
	// No INSERT INTO dns_records expected when total=0

	err = seedDatabase(context.Background(), db, 0)
	if err != nil {
		t.Errorf("seedDatabase failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestRunSeed_DBOpenFailure tests db.Open failure path
func TestRunSeed_DBOpenFailure(t *testing.T) {
	t.Setenv("DATABASE_URL", "invalid-dsn")
	// Should print "failed to connect" and return
	runSeed(1)
}

// TestRunSeed_ZoneExistsError tests ON CONFLICT DO NOTHING
func TestSeedDatabase_ZoneConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %s", err)
	}
	defer db.Close()

	// Zone insert with conflict - ON CONFLICT DO NOTHING should not error
	mock.ExpectExec("INSERT INTO dns_zones").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dns_records").WillReturnResult(sqlmock.NewResult(1, 1))

	err = seedDatabase(context.Background(), db, 1)
	if err != nil {
		t.Errorf("seedDatabase failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestRunAndCaptureScale_Mock tests runAndCaptureScale with a mocked command runner
func TestRunAndCaptureScale_Mock(t *testing.T) {
	orig := runCommand
	defer func() { runCommand = orig }()

	var buf bytes.Buffer
	// buf starts empty; SetStdout will inject expected output via mockCommand

	runCommand = func(name string, args ...string) commandRunner {
		return &mockCommand{out: &buf}
	}

	result := runAndCaptureScale("127.0.0.1:10053", 1, 1, 100, "TEST")

	if result.Throughput != "123.45" {
		t.Errorf("Expected throughput 123.45, got %s", result.Throughput)
	}
	if result.Success != "100.00" {
		t.Errorf("Expected success 100.00, got %s", result.Success)
	}
}

type mockCommand struct {
	out *bytes.Buffer
}

func (m *mockCommand) SetStdout(buf *bytes.Buffer) {
	m.out = buf
	// Inject expected output when stdout is set
	buf.WriteString("Throughput:       123.45 queries/sec\nP50 (Median):     1.2ms\nP99:              5.5ms\nReliability:      100.00%")
}

func (m *mockCommand) Run() error {
	return nil
}

func TestGoCommand_SetStdout(t *testing.T) {
	var buf bytes.Buffer
	g := &goCommand{cmd: exec.Command("echo", "test")}
	g.SetStdout(&buf)
	if g.stdou == nil {
		t.Error("expected stdou to be set")
	}
	if g.cmd.Stdout == nil {
		t.Error("expected cmd.Stdout to be set")
	}
}

func TestGoCommand_Run(t *testing.T) {
	g := &goCommand{cmd: exec.Command("true")}
	err := g.Run()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGoCommand_RunError(t *testing.T) {
	g := &goCommand{cmd: exec.Command("false")}
	err := g.Run()
	if err == nil {
		t.Error("expected error from false command")
	}
}

func TestRunScaleTest_MockedSleepAndFile(t *testing.T) {
	// Save original functions
	origSleep := sleepFn
	origRead := readFileFn
	defer func() {
		sleepFn = origSleep
		readFileFn = origRead
	}()

	// Mock sleep to be instant
	sleepFn = func(d time.Duration) {}

	// Mock file read to return empty schema
	readFileFn = func(name string) ([]byte, error) {
		return []byte{}, nil
	}

	// Set invalid DB to trigger early return after schema load
	t.Setenv("DATABASE_URL", "host=/invalid/path")
	
	// This should now run without blocking on sleep
	runScaleTest(1, 1)
}
