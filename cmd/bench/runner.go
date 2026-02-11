package main

import (
	"bytes"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
)

type Result struct {
	Throughput string
	P50        string
	P99        string
	Success    string
}

var tlds = []string{"com", "net", "org", "io", "dev", "ai", "cloud", "gov", "edu", "tr", "com.tr", "me", "info"}

func main() {
	count := flag.Int("n", 100000, "Total number of queries")
	concurrency := flag.Int("c", 200, "Concurrency level")
	flag.Parse()

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

	// 2. Heavy Seeding (10M Records)
	db, _ := sql.Open("pgx", fmt.Sprintf("postgres://postgres:password@%s:%s/clouddns?sslmode=disable", pgHost, pgPort.Port()))
	schema, _ := os.ReadFile("internal/adapters/repository/schema.sql")
	db.ExecContext(ctx, string(schema))

	fmt.Println("Seeding 10,000,000 Real-World Records (This may take a moment)...")
	zoneID := uuid.New()
	db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3)", zoneID, "bench", "root")
	
	totalRecords := 10000000
	batchSize := 5000
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
		if i % 1000000 == 0 { fmt.Printf("Progress: %d%%\n", i/100000) }
	}

	// 3. Server with Chaos & Redis
	addr := "127.0.0.1:10053"
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := repository.NewPostgresRepository(db)
	srv := server.NewServer(addr, repo, logger)
	srv.Redis = server.NewRedisCache(fmt.Sprintf("%s:%s", redisHost, redisPort.Port()), "", 0)
	srv.SimulateDBLatency = 2 * time.Millisecond // Simulate real DB jitter
	go srv.Run()

	time.Sleep(1 * time.Second)

	// 4. Ultimate Benchmark (Zipfian Traffic)
	fmt.Printf("\nExecuting Internet-Scale Benchmark (10M Pool, Zipfian Traffic)\n")
	coldRes := runAndCapture(addr, *count, *concurrency, totalRecords, "COLD")
	warmRes := runAndCapture(addr, *count, *concurrency, totalRecords, "WARM (Zipfian Hot)")

	// 5. Final Report
	fmt.Println("\n==========================================================")
	fmt.Println("          REAL-WORLD SCALE PERFORMANCE REPORT             ")
	fmt.Println("==========================================================")
	fmt.Printf("%-15s | %-15s | %-15s\n", "Metric", "Cold (DB+Jitter)", "Warm (Redis+Zipf)")
	fmt.Println("----------------------------------------------------------")
	fmt.Printf("%-15s | %-15s | %-15s\n", "Throughput", coldRes.Throughput, warmRes.Throughput)
	fmt.Printf("%-15s | %-15s | %-15s\n", "P50 Latency", coldRes.P50, warmRes.P50)
	fmt.Printf("%-15s | %-15s | %-15s\n", "P99 Latency", coldRes.P99, warmRes.P99)
	fmt.Printf("%-15s | %-15s | %-15s\n", "Reliability", coldRes.Success, warmRes.Success)
	fmt.Println("==========================================================\n")
}

func runAndCapture(addr string, n int, c int, rangeLimit int, phase string) Result {
	fmt.Printf("Running Phase: %s...\n", phase)
	args := []string{"run", "cmd/bench/main.go", "-server", addr, "-n", strconv.Itoa(n), "-c", strconv.Itoa(c), "-range", strconv.Itoa(rangeLimit)}
	
	cmd := exec.Command("go", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	cmd.Run()

	output := out.String()
	fmt.Print(output)

	return Result{
		Throughput: extract(output, `Throughput:\s+([0-9.]+)`),
		P50:        extract(output, `P50 \(Median\):\s+([0-9a-z.]+)`),
		P99:        extract(output, `P99:\s+([0-9a-z.]+)`),
		Success:    extract(output, `Reliability:\s+([0-9.]+)%`),
	}
}

func extract(data string, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(data)
	if len(match) > 1 { return match[1] }
	return "N/A"
}
