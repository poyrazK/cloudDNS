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
	count := flag.Int("n", 1000, "Total number of queries")
	concurrency := flag.Int("c", 10, "Concurrency level")
	randomize := flag.Bool("random", false, "Randomize subdomains")
	flag.Parse()

	ctx := context.Background()

	// 1. Start Temporary PostgreSQL using Testcontainers
	fmt.Println("Starting Temporary PostgreSQL Container...")
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "password",
			"POSTGRES_DB":       "clouddns",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}
	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Printf("Failed to start postgres: %v\n", err)
		os.Exit(1)
	}
	defer pgContainer.Terminate(ctx)

	host, _ := pgContainer.Host(ctx)
	port, _ := pgContainer.MappedPort(ctx, "5432")
	dbURL := fmt.Sprintf("postgres://postgres:password@%s:%s/clouddns?sslmode=disable", host, port.Port())

	// 2. Initialize Schema
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		fmt.Printf("Failed to connect to db: %v\n", err)
		os.Exit(1)
	}
	
	schema, _ := os.ReadFile("internal/adapters/repository/schema.sql")
	if _, err := db.ExecContext(ctx, string(schema)); err != nil {
		fmt.Printf("Failed to init schema: %v\n", err)
		os.Exit(1)
	}

	// 3. Seed 10,000 Records
	fmt.Println("Seeding 10,000 records for 'test.com'...")
	zoneID := uuid.New()
	db.ExecContext(ctx, "INSERT INTO dns_zones (id, tenant_id, name) VALUES ($1, $2, $3)", zoneID, "bench", "test.com")
	
	stmt, _ := db.PrepareContext(ctx, "INSERT INTO dns_records (id, zone_id, name, type, content, ttl) VALUES ($1, $2, $3, $4, $5, $6)")
	for i := 0; i < 10000; i++ {
		stmt.ExecContext(ctx, uuid.New(), zoneID, fmt.Sprintf("req-%d.test.com", i), "A", "1.2.3.4", 3600)
	}
	stmt.Close()

	// 4. Start Server with Real PostgreSQL Repository
	addr := "127.0.0.1:10053"
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	repo := repository.NewPostgresRepository(db)
	srv := server.NewServer(addr, repo, logger)

	fmt.Printf("Starting CloudDNS Production-Grade Server on %s\n", addr)
	go func() {
		if err := srv.Run(); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	time.Sleep(1 * time.Second)

	// 5. Run Benchmark
	fmt.Printf("Executing REAL-WORLD Scaling Test: %d queries | %d concurrency | Random: %v\n", *count, *concurrency, *randomize)
	
	args := []string{"run", "cmd/bench/main.go", 
		"-server", addr, 
		"-n", strconv.Itoa(*count), 
		"-c", strconv.Itoa(*concurrency)}
	if *randomize {
		args = append(args, "-random")
	}

	benchCmd := exec.Command("go", args...)
	benchCmd.Stdout = os.Stdout
	benchCmd.Stderr = os.Stderr
	
	if err := benchCmd.Run(); err != nil {
		fmt.Printf("Benchmark failed: %v\n", err)
	}

	fmt.Println("\nBenchmark Complete. Shutting down container.")
}
