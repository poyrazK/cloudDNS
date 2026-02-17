package main

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

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
}

var tlds = []string{"com", "net", "org", "io", "dev", "ai", "cloud", "gov", "edu", "tr", "com.tr", "me", "info"}

func main() {
	mode := flag.String("mode", "bench", "Mode: bench, scale-test, or seed")
	target := flag.String("server", "127.0.0.1:10053", "DNS server to test")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	count := flag.Int("n", 1000, "Total number of queries to send")
	rangeLimit := flag.Int("range", 10000000, "Number of records in the database (default 10M)")
	zipfS := flag.Float64("zipf-s", 1.1, "Zipf distribution constant (s > 1). Higher means more 'Hot' domains.")
	zipfV := flag.Float64("zipf-v", 100, "Zipf distribution constant (v >= 1).")
	flag.Parse()

	switch *mode {
	case "seed":
		runSeed(*rangeLimit)
	case "scale-test":
		runScaleTest(*count, *concurrency)
	default:
		runBenchmark(*target, *count, *concurrency, uint64(*rangeLimit), *zipfS, *zipfV)
	}
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

	printEnhancedReport(duration, &stats, concurrency)
}

func runRealisticWorker(target string, count int, workerID int, rangeLimit uint64, s float64, v float64, stats *Stats) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		fmt.Printf("Connection error: %v\n", err)
		return
	}
	defer conn.Close()

	recvBuf := make([]byte, 1024)
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
	zipf := rand.NewZipf(r, s, v, rangeLimit-1)

	for i := 0; i < count; i++ {
		idx := zipf.Uint64()
		currentDomain := fmt.Sprintf("host-%d.%s", idx, tlds[idx%uint64(len(tlds))])

		p := packet.NewDNSPacket()
		p.Header.ID = uint16(r.Uint32())
		p.Questions = append(p.Questions, packet.DNSQuestion{Name: currentDomain, QType: packet.A})

		buf := packet.NewBytePacketBuffer()
		p.Write(buf)
		data := buf.Buf[:buf.Position()]

		queryStart := time.Now()
		
		n, err := conn.Write(data)
		if err != nil {
			atomic.AddUint64(&stats.Errors, 1)
			continue
		}
		atomic.AddUint64(&stats.BytesSent, uint64(n))

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err = conn.Read(recvBuf)
		
		if err != nil {
			atomic.AddUint64(&stats.Errors, 1)
		} else {
			atomic.AddUint64(&stats.Success, 1)
			atomic.AddUint64(&stats.BytesReceived, uint64(n))
			stats.Latencies <- time.Since(queryStart)
		}
		atomic.AddUint64(&stats.TotalQueries, 1)
	}
}

func printEnhancedReport(duration time.Duration, stats *Stats, concurrency int) {
	qps := float64(stats.Success) / duration.Seconds()
	mbSent := float64(stats.BytesSent) / 1024 / 1024
	mbRecv := float64(stats.BytesReceived) / 1024 / 1024
	
	var latencies []time.Duration
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

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		fmt.Printf("failed to connect: %v\n", err)
		return
	}
	defer db.Close()

	if err := seedDatabase(context.Background(), db, total); err != nil {
		fmt.Printf("Seeding failed: %v\n", err)
	} else {
		fmt.Println("Seeding Completed Successfully.")
	}
}

func seedDatabase(ctx context.Context, db *sql.DB, total int) error {
	zoneID := uuid.New()
	
	fmt.Println("Preparing record environment...")
	
	db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", zoneID, "bench", "root")

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

		query := fmt.Sprintf("INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES %s", strings.Join(valueStrings, ","))
		_, err := db.ExecContext(ctx, query, valueArgs...)
		if err != nil {
			return err
		}

		if i%100000 == 0 && i > 0 {
			fmt.Printf("Progress: %d/%d (%.1f%%)\n", i, total, float64(i)/float64(total)*100)
		}
	}
	return nil
}

func runScaleTest(count int, concurrency int) {
	ctx := context.Background()

	// 1. Infrastructure
	fmt.Println("Starting Internet-Scale Infrastructure...")
	pgContainer, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "postgres:16-alpine", ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{"POSTGRES_PASSWORD": "password", "POSTGRES_DB": "clouddns"},
			WaitingFor: wait.ForListeningPort("5432/tcp"),
		},
		Started: true,
	})
	defer pgContainer.Terminate(ctx)

	redisContainer, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"},
			WaitingFor: wait.ForListeningPort("6379/tcp"),
		},
		Started: true,
	})
	defer redisContainer.Terminate(ctx)

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	redisHost, _ := redisContainer.Host(ctx)
	redisPort, _ := redisContainer.MappedPort(ctx, "6379")

	// 2. Heavy Seeding
	db, _ := sql.Open("pgx", fmt.Sprintf("postgres://postgres:password@%s:%s/clouddns?sslmode=disable", pgHost, pgPort.Port()))
	schema, _ := os.ReadFile("internal/adapters/repository/schema.sql")
	db.ExecContext(ctx, string(schema))

	zoneID := uuid.New()
	db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3)", zoneID, "bench", "root")
	
	totalRecords := 1000000
	batchSize := 10000
	for i := 0; i < totalRecords; i += batchSize {
		vals := []string{}
		args := []interface{}{}
		for j := 0; j < batchSize; j++ {
			idx := i + j
			name := fmt.Sprintf("host-%d.%s", idx, tlds[idx%len(tlds)])
			off := len(args)
			vals = append(vals, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)", off+1, off+2, off+3, off+4, off+5, off+6))
			args = append(args, uuid.New(), zoneID, name, "A", "1.2.3.4", 3600)
		}
		query := fmt.Sprintf("INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES %s", strings.Join(vals, ","))
		db.ExecContext(ctx, query, args...)
	}

	// 3. Server
	addr := "127.0.0.1:10053"
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := repository.NewPostgresRepository(db)
	srv := server.NewServer(addr, repo, logger)
	srv.Redis = server.NewRedisCache(fmt.Sprintf("%s:%s", redisHost, redisPort.Port()), "", 0)
	go srv.Run()

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

func runAndCaptureScale(addr string, n int, c int, rangeLimit int, phase string) Result {
	fmt.Printf("Running Phase: %s...\n", phase)
	args := []string{"run", "cmd/bench/main.go", "-server", addr, "-n", strconv.Itoa(n), "-c", strconv.Itoa(c), "-range", strconv.Itoa(rangeLimit)}
	cmd := exec.Command("go", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
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
