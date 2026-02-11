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

func main() {
	count := flag.Int("n", 100000, "Total number of queries")
	concurrency := flag.Int("c", 200, "Concurrency level")
	flag.Parse()

	ctx := context.Background()

	// 1. Start Containers
	fmt.Println("Starting Infrastructure (Postgres + Redis)...")
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

	host, _ := redisContainer.Host(ctx)
	redisPort, _ := redisContainer.MappedPort(ctx, "6379")
	redisAddr := fmt.Sprintf("%s:%s", host, redisPort.Port())

	host, _ = pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	dbURL := fmt.Sprintf("postgres://postgres:password@%s:%s/clouddns?sslmode=disable", host, pgPort.Port())

	// 2. Setup Data
	db, _ := sql.Open("pgx", dbURL)
	schema, _ := os.ReadFile("internal/adapters/repository/schema.sql")
	db.ExecContext(ctx, string(schema))

	fmt.Println("Seeding 10,000 records...")
	zoneID := uuid.New()
	db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3)", zoneID, "bench", "test.com")
	stmt, _ := db.PrepareContext(ctx, "INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES ($1, $2, $3, $4, $5, $6)")
	for i := 0; i < 10000; i++ {
		stmt.ExecContext(ctx, uuid.New(), zoneID, fmt.Sprintf("req-%d.test.com", i), "A", "1.2.3.4", 3600)
	}
	stmt.Close()

	// 3. Start Server
	addr := "127.0.0.1:10053"
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := repository.NewPostgresRepository(db)
	srv := server.NewServer(addr, repo, logger)
	srv.Redis = server.NewRedisCache(redisAddr, "", 0)
	go srv.Run()

	time.Sleep(1 * time.Second)

	// 4. Run Phases
	fmt.Printf("\nExecuting 100k Benchmark: Cold vs Warm\n")
	
	coldRes := runAndCapture(addr, *count, *concurrency, 10000, "COLD")
	warmRes := runAndCapture(addr, *count, *concurrency, 10000, "WARM")

	// 5. Final Comparison Table
	fmt.Println("\n==========================================================")
	fmt.Println("          TIERED-CACHE PERFORMANCE COMPARISON             ")
	fmt.Println("==========================================================")
	fmt.Printf("%-15s | %-15s | %-15s\n", "Metric", "Cold (DB)", "Warm (Redis)")
	fmt.Println("----------------------------------------------------------")
	fmt.Printf("%-15s | %-15s | %-15s\n", "Throughput", coldRes.Throughput, warmRes.Throughput)
	fmt.Printf("%-15s | %-15s | %-15s\n", "P50 Latency", coldRes.P50, warmRes.P50)
	fmt.Printf("%-15s | %-15s | %-15s\n", "P99 Latency", coldRes.P99, warmRes.P99)
	fmt.Printf("%-15s | %-15s | %-15s\n", "Reliability", coldRes.Success, warmRes.Success)
	fmt.Println("==========================================================\n")
}

func runAndCapture(addr string, n int, c int, rangeLimit int, phase string) Result {
	fmt.Printf("Running Phase: %s...\n", phase)
	args := []string{"run", "cmd/bench/main.go", "-server", addr, "-n", strconv.Itoa(n), "-c", strconv.Itoa(c), "-random", "-range", strconv.Itoa(rangeLimit)}
	
	cmd := exec.Command("go", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	cmd.Run()

	output := out.String()
	fmt.Print(output) // Still print details to console

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
	if len(match) > 1 {
		return match[1]
	}
	return "N/A"
}
