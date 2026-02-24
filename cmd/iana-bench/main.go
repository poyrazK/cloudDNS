package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"math/rand"
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
	defer db.Close()

	fmt.Println("Fetching domain names from database...")
	rows, err := db.Query("SELECT DISTINCT name FROM dns_records WHERE name != '.'")
	if err != nil {
		log.Fatalf("failed to fetch names: %v", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		log.Fatal("No names found in database. Run iana-import first.")
	}

	fmt.Printf("Starting stress test: %d queries, %d concurrency using %d unique names\n", *count, *concurrency, len(names))

	var success, errors uint64
	var wg sync.WaitGroup
	start := time.Now()

	queriesPerWorker := *count / *concurrency

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			conn, err := net.Dial("udp", *target)
			if err != nil {
				return
			}
			defer conn.Close()

			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			
			for j := 0; j < queriesPerWorker; j++ {
				name := names[r.Intn(len(names))]
				
				p := packet.NewDNSPacket()
				p.Header.ID = uint16(r.Uint32())
				p.Questions = append(p.Questions, packet.DNSQuestion{Name: name, QType: packet.NS})

				buf := packet.NewBytePacketBuffer()
				_ = p.Write(buf)
				data := buf.Buf[:buf.Position()]

				_, err := conn.Write(data)
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
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	fmt.Printf("\n--- Stress Test Results ---\n")
	fmt.Printf("Total Queries: %d\n", *count)
	fmt.Printf("Successful:    %d\n", success)
	fmt.Printf("Failed:        %d\n", errors)
	fmt.Printf("Time Taken:    %v\n", duration)
	fmt.Printf("Throughput:    %.2f queries/sec\n", float64(success)/duration.Seconds())
	fmt.Printf("Reliability:   %.2f%%\n", (float64(success)/float64(*count))*100)
}
