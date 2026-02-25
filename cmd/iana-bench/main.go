package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

func main() {
	target := flag.String("server", "127.0.0.1:10053", "DNS server to test")
	count := flag.Int("n", 10000, "Total number of queries to send")
	concurrency := flag.Int("c", 50, "Number of concurrent workers")
	flag.Parse()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer func() {
		if errClose := db.Close(); errClose != nil {
			log.Printf("failed to close database: %v", errClose)
		}
	}()

	if err := RunBench(db, *target, *count, *concurrency); err != nil {
		log.Fatalf("benchmark failed: %v", err)
	}
}

func RunBench(db *sql.DB, target string, count, concurrency int) error {
	fmt.Println("Fetching domain names from database...")
	rows, err := db.Query("SELECT DISTINCT name FROM dns_records WHERE name != '.'")
	if err != nil {
		return fmt.Errorf("failed to fetch names: %w", err)
	}
	defer func() {
		if errClose := rows.Close(); errClose != nil {
			log.Printf("failed to close rows: %v", errClose)
		}
	}()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return fmt.Errorf("no names found in database")
	}

	fmt.Printf("Starting stress test: %d queries, %d concurrency using %d unique names\n", count, concurrency, len(names))

	var success, errors uint64
	var wg sync.WaitGroup
	start := time.Now()

	queriesPerWorker := count / concurrency

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			conn, err := net.Dial("udp", target)
			if err != nil {
				return
			}
			defer func() {
				if errClose := conn.Close(); errClose != nil {
					log.Printf("failed to close connection: %v", errClose)
				}
			}()

			for j := 0; j < queriesPerWorker; j++ {
				n, errRand := rand.Int(rand.Reader, big.NewInt(int64(len(names))))
				if errRand != nil {
					continue
				}
				name := names[n.Int64()]
				
				p := packet.NewDNSPacket()
				var idBytes [2]byte
				_, _ = rand.Read(idBytes[:])
				p.Header.ID = binary.BigEndian.Uint16(idBytes[:])
				p.Questions = append(p.Questions, packet.DNSQuestion{Name: name, QType: packet.NS})

				buf := packet.NewBytePacketBuffer()
				_ = p.Write(buf)
				data := buf.Buf[:buf.Position()]

				_, err = conn.Write(data)
				if err != nil {
					atomic.AddUint64(&errors, 1)
					continue
				}

				_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				recvBuf := make([]byte, 1024)
				_, err = conn.Read(recvBuf)
				if err != nil {
					atomic.AddUint64(&errors, 1)
				} else {
					atomic.AddUint64(&success, 1)
				}
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	fmt.Printf("\n--- Stress Test Results ---\n")
	fmt.Printf("Total Queries: %d\n", count)
	fmt.Printf("Successful:    %d\n", success)
	fmt.Printf("Failed:        %d\n", errors)
	fmt.Printf("Time Taken:    %v\n", duration)
	fmt.Printf("Throughput:    %.2f queries/sec\n", float64(success)/duration.Seconds())
	fmt.Printf("Reliability:   %.2f%%\n", (float64(success)/float64(count))*100)
	return nil
}
