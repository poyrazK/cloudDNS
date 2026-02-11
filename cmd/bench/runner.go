package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/poyrazK/cloudDNS/internal/adapters/repository"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
)

func main() {
	count := flag.Int("n", 10000, "Total number of queries")
	concurrency := flag.Int("c", 100, "Concurrency level")
	flag.Parse()

	ctx := context.Background()

	// 1. Start PostgreSQL
	fmt.Println("Starting PostgreSQL Container...")
	pgReq := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "password",
			"POSTGRES_DB":       "clouddns",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}
	pgContainer, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: pgReq,
		Started:          true,
	})
	defer pgContainer.Terminate(ctx)

	host, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	dbURL := fmt.Sprintf("postgres://postgres:password@%s:%s/clouddns?sslmode=disable", host, pgPort.Port())

	// 2. Start Redis
	fmt.Println("Starting Redis Container...")
	redisReq := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp"),
	}
	redisContainer, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	defer redisContainer.Terminate(ctx)

	redisHost, _ := redisContainer.Host(ctx)
	redisPort, _ := redisContainer.MappedPort(ctx, "6379")
	redisAddr := fmt.Sprintf("%s:%s", redisHost, redisPort.Port())

	// 3. Setup Schema & Seed 10,000 Records
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

	// 4. Start Server
	addr := "127.0.0.1:10053"
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := repository.NewPostgresRepository(db)
	srv := server.NewServer(addr, repo, logger)
	srv.Redis = server.NewRedisCache(redisAddr, "", 0)
	go srv.Run()

	time.Sleep(1 * time.Second)

	// 5. Phase 1: Cold Run (Postgres + Redis Population)
	fmt.Println("\n--- PHASE 1: COLD RUN (Database Driven) ---")
	runBench(addr, *count, *concurrency, true, 10000)

	// 6. Phase 2: Warm Run (Redis Driven)
	fmt.Println("\n--- PHASE 2: WARM RUN (Redis Driven) ---")
	runBench(addr, *count, *concurrency, true, 10000)

	fmt.Println("\nValidation Complete.")
}

func runBench(addr string, n int, c int, random bool, rangeLimit int) {
	args := []string{"run", "cmd/bench/main.go", "-server", addr, "-n", strconv.Itoa(n), "-c", strconv.Itoa(c)}
	if random {
		args = append(args, "-random")
	}
	if rangeLimit > 0 {
		args = append(args, "-range", strconv.Itoa(rangeLimit))
	}

	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
