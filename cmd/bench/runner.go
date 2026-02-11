package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/server"
)

type mockRepo struct{}

func (m *mockRepo) GetRecords(ctx context.Context, name string, qType domain.RecordType, clientIP string) ([]domain.Record, error) {
	return []domain.Record{
		{Name: name, Type: domain.TypeA, Content: "1.2.3.4", TTL: 3600},
	}, nil
}

func (m *mockRepo) GetIPsForName(ctx context.Context, name string, clientIP string) ([]string, error) {
	return []string{"1.2.3.4"}, nil
}

func (m *mockRepo) CreateZone(ctx context.Context, zone *domain.Zone) error { return nil }
func (m *mockRepo) CreateZoneWithRecords(ctx context.Context, zone *domain.Zone, records []domain.Record) error { return nil }
func (m *mockRepo) CreateRecord(ctx context.Context, record *domain.Record) error { return nil }
func (m *mockRepo) ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error) { return nil, nil }
func (m *mockRepo) DeleteZone(ctx context.Context, zoneID string, tenantID string) error { return nil }
func (m *mockRepo) DeleteRecord(ctx context.Context, recordID string, zoneID string) error { return nil }
func (m *mockRepo) SaveAuditLog(ctx context.Context, log *domain.AuditLog) error { return nil }
func (m *mockRepo) GetAuditLogs(ctx context.Context, tenantID string) ([]domain.AuditLog, error) { return nil, nil }
func (m *mockRepo) Ping(ctx context.Context) error { return nil }

func main() {
	count := flag.Int("n", 1000, "Total number of queries")
	concurrency := flag.Int("c", 10, "Concurrency level")
	flag.Parse()

	addr := "127.0.0.1:10053"
	// Silent logger for benchmark to avoid console spam
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	
	repo := &mockRepo{}
	srv := server.NewServer(addr, repo, logger)

	fmt.Printf("Starting CloudDNS Benchmark Server on %s\n", addr)
	go func() {
		if err := srv.Run(); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	}()

	// Give server a moment to start
	time.Sleep(500 * time.Millisecond)

	fmt.Printf("Executing Scaling Test: %d queries | %d concurrency\n", *count, *concurrency)
	
	cmd := exec.Command("go", "run", "cmd/bench/main.go", 
		"-server", addr, 
		"-n", strconv.Itoa(*count), 
		"-c", strconv.Itoa(*concurrency))
	
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		fmt.Printf("Benchmark failed: %v\n", err)
	}

	fmt.Println("\nBenchmark Complete. Shutting down server.")
}
