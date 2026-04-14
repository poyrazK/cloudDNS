package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
)

type Stats struct {
	TotalQueries  uint64
	Success       uint64
	Errors        uint64
	BytesSent     uint64
	BytesReceived uint64
	Latencies     chan time.Duration
}

type Result struct {
	Throughput string
	P50        string
	P99        string
	Success    string
	Err       string
}

var tlds = []string{"com", "net", "org", "io", "dev", "ai", "cloud", "gov", "edu", "tr", "com.tr", "me", "info"}

func main() {
	if err := Run(os.Args); err != nil {
		fmt.Printf("benchmark failed: %v\n", err)
		os.Exit(1)
	}
}

func Run(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	mode := fs.String("mode", "bench", "Mode: bench, scale-test, or seed")
	target := fs.String("server", "127.0.0.1:10053", "DNS server to test")
	concurrency := fs.Int("c", 10, "Number of concurrent workers")
	count := fs.Int("n", 1000, "Total number of queries to send")
	rangeLimit := fs.Int("range", 10000000, "Number of records in the database (default 10M)")
	zipfS := fs.Float64("zipf-s", 1.1, "Zipf distribution constant (s > 1). Higher means more 'Hot' domains.")
	zipfV := fs.Float64("zipf-v", 100, "Zipf distribution constant (v >= 1).")
	
	var parseArgs []string
	if len(args) > 1 {
		parseArgs = args[1:]
	} else {
		parseArgs = []string{}
	}
	
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}

	switch *mode {
	case "seed":
		runSeed(*rangeLimit)
	case "scale-test":
		runScaleTest(*count, *concurrency)
	default:
		runBenchmark(*target, *count, *concurrency, uint64(*rangeLimit), *zipfS, *zipfV) // #nosec G115
	}
	return nil
}

func runBenchmark(target string, count int, concurrency int, rangeLimit uint64, s float64, v float64) {
	fmt.Printf("Starting Realistic Benchmark\n")
	fmt.Printf("Configuration: %d queries | %d concurrency | Pool Size: %d | Zipf(s=%.1f, v=%.1f)\n", count, concurrency, rangeLimit, s, v)

	stats := Stats{
		Latencies: make(chan time.Duration, count),
	}

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(concurrency)

	queriesPerWorker := count / concurrency

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			runRealisticWorker(target, queriesPerWorker, workerID, rangeLimit, s, v, &stats)
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)
	close(stats.Latencies)

	printEnhancedReport(duration, &stats, concurrency, count)
}

func runRealisticWorker(target string, count int, workerID int, rangeLimit uint64, s float64, v float64, stats *Stats) {
	conn, errDial := net.Dial("udp", target)
	if errDial != nil {
		fmt.Printf("Connection error: %v\n", errDial)
		return
	}
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			fmt.Printf("Warning: failed to close connection: %v\n", errClose)
		}
	}()

	recvBuf := make([]byte, 1024)
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID))) // #nosec G404
	zipf := rand.NewZipf(r, s, v, rangeLimit-1)

	for i := 0; i < count; i++ {
		idx := zipf.Uint64()
		currentDomain := fmt.Sprintf("host-%d.%s", idx, tlds[idx%uint64(len(tlds))])

		p := packet.NewDNSPacket()
		p.Header.ID = uint16(r.Uint32()) // #nosec G115
		p.Questions = append(p.Questions, packet.DNSQuestion{Name: currentDomain, QType: packet.A})

		buf := packet.NewBytePacketBuffer()
		if errWrite := p.Write(buf); errWrite != nil {
			atomic.AddUint64(&stats.Errors, 1)
			continue
		}
		data := buf.Buf[:buf.Position()]

		queryStart := time.Now()
		
		n, errWrite := conn.Write(data)
		if errWrite != nil {
			atomic.AddUint64(&stats.Errors, 1)
			continue
		}
		atomic.AddUint64(&stats.BytesSent, uint64(n)) // #nosec G115

		if errDeadline := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); errDeadline != nil {
			fmt.Printf("Warning: failed to set read deadline: %v\n", errDeadline)
		}
		n, errRead := conn.Read(recvBuf)
		
		if errRead != nil {
			atomic.AddUint64(&stats.Errors, 1)
		} else {
			atomic.AddUint64(&stats.Success, 1)
			atomic.AddUint64(&stats.BytesReceived, uint64(n)) // #nosec G115
			stats.Latencies <- time.Since(queryStart)
		}
		atomic.AddUint64(&stats.TotalQueries, 1)
	}
}

func printEnhancedReport(duration time.Duration, stats *Stats, concurrency int, count int) {
	qps := float64(stats.Success) / duration.Seconds()
	mbSent := float64(stats.BytesSent) / 1024 / 1024
	mbRecv := float64(stats.BytesReceived) / 1024 / 1024
	
	latencies := make([]time.Duration, 0, count)
	for l := range stats.Latencies {
		latencies = append(latencies, l)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Println("\n============================================")
	fmt.Println("          DNS ENGINE PERFORMANCE REPORT       ")
	fmt.Println("============================================")
	fmt.Printf("Test Duration:    %v\n", duration)
	fmt.Printf("Concurrency:      %d workers\n", concurrency)
	fmt.Printf("Throughput:       %.2f queries/sec\n", qps)
	fmt.Printf("Data Transfer:    %.2f MB Sent | %.2f MB Received\n", mbSent, mbRecv)
	
	fmt.Println("\n--- Query Statistics ---")
	fmt.Printf("Total Attempted:  %d\n", stats.TotalQueries)
	fmt.Printf("Successful:       %d\n", stats.Success)
	fmt.Printf("Failed/Timed out: %d\n", stats.Errors)
	if stats.TotalQueries > 0 {
		fmt.Printf("Reliability:      %.2f%%\n", (float64(stats.Success)/float64(stats.TotalQueries))*100)
	}

	if len(latencies) > 0 {
		fmt.Println("\n--- Latency Percentiles ---")
		fmt.Printf("P50 (Median):     %v\n", latencies[len(latencies)/2])
		fmt.Printf("P90:              %v\n", latencies[int(float64(len(latencies))*0.90)])
		fmt.Printf("P95:              %v\n", latencies[int(float64(len(latencies))*0.95)])
		fmt.Printf("P99:              %v\n", latencies[int(float64(len(latencies))*0.99)])
		fmt.Printf("Min:              %v\n", latencies[0])
		fmt.Printf("Max:              %v\n", latencies[len(latencies)-1])
	}
	fmt.Println("============================================")
}

func runSeed(total int) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:password@localhost:5432/clouddns?sslmode=disable"
	}

	db, errConn := sql.Open("pgx", dbURL)
	if errConn != nil {
		fmt.Printf("failed to connect: %v\n", errConn)
		return
	}
	defer func() { _ = db.Close() }()

	if errSeed := seedDatabase(context.Background(), db, total); errSeed != nil {
		fmt.Printf("Seeding failed: %v\n", errSeed)
	} else {
		fmt.Println("Seeding Completed Successfully.")
	}
}

func seedDatabase(ctx context.Context, db *sql.DB, total int) error {
	zoneID := uuid.New()
	
	fmt.Println("Preparing record environment...")
	
	if _, err := db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", zoneID, "bench", "root"); err != nil {
		return fmt.Errorf("failed to ensure root zone: %w", err)
	}

	batchSize := 5000 
	fmt.Printf("Seeding %d Realistic Records...\n", total)

	for i := 0; i < total; i += batchSize {
		valueStrings := make([]string, 0, batchSize)
		valueArgs := make([]interface{}, 0, batchSize*6)
		
		for j := 0; j < batchSize; j++ {
			idx := i + j
			if idx >= total { break }
			offset := len(valueArgs)
			name := fmt.Sprintf("host-%d.%s", idx, tlds[idx%len(tlds)])
			valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)", offset+1, offset+2, offset+3, offset+4, offset+5, offset+6))
			valueArgs = append(valueArgs, uuid.New(), zoneID, name, "A", "1.2.3.4", 3600)
		}

		if len(valueStrings) == 0 { break }

		// #nosec G201
		query := fmt.Sprintf("INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES %s", strings.Join(valueStrings, ","))
		_, errExec := db.ExecContext(ctx, query, valueArgs...)
		if errExec != nil {
			return errExec
		}

		if i%100000 == 0 && i > 0 {
			fmt.Printf("Progress: %d/%d (%.1f%%)\n", i, total, float64(i)/float64(total)*100)
		}
	}
	return nil
}

func runScaleTest(count int, concurrency int) {
	ctx := context.Background()

	// Use external dependencies instead of starting containers
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:password@localhost:5432/clouddns?sslmode=disable"
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	fmt.Printf("Starting Scale Test (using %s and %s)...\n", dbURL, redisURL)

	// 2. Heavy Seeding
	db, errDB := sql.Open("pgx", dbURL)
	if errDB != nil {
		fmt.Printf("Failed to connect to database: %v\n", errDB)
		return
	}
	defer func() { _ = db.Close() }()

	schema, errRead := os.ReadFile("internal/adapters/repository/schema.sql")
	if errRead != nil {
		fmt.Printf("Failed to read schema file: %v\n", errRead)
		return
	}
	if _, errSchema := db.ExecContext(ctx, string(schema)); errSchema != nil {
		fmt.Printf("Failed to load schema: %v\n", errSchema)
		return
	}

	zoneID := uuid.New()
	if _, errZone := db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3)", zoneID, "bench", "root"); errZone != nil {
		fmt.Printf("Failed to create root zone: %v\n", errZone)
		return
	}
	
	totalRecords := 1000000
	batchSize := 10000
	for i := 0; i < totalRecords; i += batchSize {
		vals := []string{}
		args := []interface{}{}
		for j := 0; j < batchSize; j++ {
			idx := i + j
			if idx >= totalRecords { break }
			name := fmt.Sprintf("host-%d.%s", idx, tlds[idx%len(tlds)])
			off := len(args)
			vals = append(vals, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)", off+1, off+2, off+3, off+4, off+5, off+6))
			args = append(args, uuid.New(), zoneID, name, "A", "1.2.3.4", 3600)
		}
		if len(vals) == 0 { break }
		// #nosec G201
		query := fmt.Sprintf("INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES %s", strings.Join(vals, ","))
		if _, errExec := db.ExecContext(ctx, query, args...); errExec != nil {
			fmt.Printf("Batch insertion failed at record %d: %v\n", i, errExec)
			return
		}
	}

	// 3. Server
	addr := "127.0.0.1:10053"
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := repository.NewPostgresRepository(db)
	srv := server.NewServer(addr, repo, logger)
	srv.Redis = server.NewRedisCache(redisURL, "", 0)
	
	srvCtx, cancelSrv := context.WithCancel(ctx)
	defer cancelSrv()
	go func() {
		if err := srv.Run(srvCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("server failed during scale test", "error", err)
		}
	}()

	time.Sleep(1 * time.Second)

	// 4. Benchmark
	fmt.Printf("\nExecuting Internet-Scale Benchmark\n")
	coldRes := runAndCaptureScale(addr, count, concurrency, totalRecords, "COLD")
	warmRes := runAndCaptureScale(addr, count, concurrency, totalRecords, "WARM")

	// 5. Final Report
	fmt.Println("\n==========================================================")
	fmt.Println("          REAL-WORLD SCALE PERFORMANCE REPORT             ")
	fmt.Println("==========================================================")
	fmt.Printf("%-15s | %-15s | %-15s\n", "Metric", "Cold", "Warm")
	fmt.Println("----------------------------------------------------------")
	fmt.Printf("%-15s | %-15s | %-15s\n", "Throughput", coldRes.Throughput, warmRes.Throughput)
	fmt.Printf("%-15s | %-15s | %-15s\n", "P50 Latency", coldRes.P50, warmRes.P50)
	fmt.Printf("%-15s | %-15s | %-15s\n", "P99 Latency", coldRes.P99, warmRes.P99)
	fmt.Printf("%-15s | %-15s | %-15s\n", "Reliability", coldRes.Success, warmRes.Success)
	fmt.Println("==========================================================")
}

type commandRunner interface {
	Run() error
	SetStdout(*bytes.Buffer)
}

type goCommand struct {
	cmd   *exec.Cmd
	stdou *bytes.Buffer
}

func (g *goCommand) SetStdout(buf *bytes.Buffer) {
	g.stdou = buf
	g.cmd.Stdout = buf
}

func (g *goCommand) Run() error {
	return g.cmd.Run()
}

var runCommand func(string, ...string) commandRunner = func(name string, args ...string) commandRunner {
	return &goCommand{cmd: exec.Command(name, args...)}
}

func runAndCaptureScale(addr string, n int, c int, rangeLimit int, phase string) Result {
	fmt.Printf("Running Phase: %s...\n", phase)
	cmd := runCommand("go", "run", "cmd/bench/main.go", "-server", addr, "-n", strconv.Itoa(n), "-c", strconv.Itoa(c), "-range", strconv.Itoa(rangeLimit))
	var out bytes.Buffer
	cmd.SetStdout(&out)
	if err := cmd.Run(); err != nil {
		return Result{Err: err.Error()}
	}
	output := out.String()
	return Result{
		Throughput: extractRegex(output, `Throughput:\s+([0-9.]+)`),
		P50:        extractRegex(output, `P50 \(Median\):\s+([0-9a-z.]+)`),
		P99:        extractRegex(output, `P99:\s+([0-9a-z.]+)`),
		Success:    extractRegex(output, `Reliability:\s+([0-9.]+)%`),
	}
}

func extractRegex(data string, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(data)
	if len(match) > 1 { return match[1] }
	return "N/A"
}
