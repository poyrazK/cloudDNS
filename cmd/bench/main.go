package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type Stats struct {
	TotalQueries uint64
	Success      uint64
	Errors       uint64
	Latencies    chan time.Duration
}

func main() {
	target := flag.String("server", "127.0.0.1:1053", "DNS server to test")
	domain := flag.String("domain", "test.com", "Domain to query")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	count := flag.Int("n", 1000, "Total number of queries to send")
	flag.Parse()

	fmt.Printf("Starting scaling test: %d queries, %d concurrency, targeting %s\n", *count, *concurrency, *target)

	stats := Stats{
		Latencies: make(chan time.Duration, *count),
	}

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(*concurrency)

	queriesPerWorker := *count / *concurrency

	for i := 0; i < *concurrency; i++ {
		go func() {
			defer wg.Done()
			runWorker(*target, *domain, queriesPerWorker, &stats)
		}()
	}

	wg.Wait()
	duration := time.Since(start)
	close(stats.Latencies)

	printReport(duration, &stats)
}

func runWorker(target string, domainName string, count int, stats *Stats) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		fmt.Printf("Connection error: %v\n", err)
		return
	}
	defer conn.Close()

	// Pre-build packet to minimize worker overhead
	p := packet.NewDnsPacket()
	p.Header.ID = 1234
	p.Header.RecursionDesired = true
	p.Questions = append(p.Questions, *packet.NewDnsQuestion(domainName, packet.A))

	buf := packet.NewBytePacketBuffer()
	p.Write(buf)
	data := buf.Buf[:buf.Position()]

	recvBuf := make([]byte, 512)

	for i := 0; i < count; i++ {
		queryStart := time.Now()
		
		_, err := conn.Write(data)
		if err != nil {
			atomic.AddUint64(&stats.Errors, 1)
			continue
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(recvBuf)
		
		if err != nil {
			atomic.AddUint64(&stats.Errors, 1)
		} else {
			atomic.AddUint64(&stats.Success, 1)
			stats.Latencies <- time.Since(queryStart)
		}
		atomic.AddUint64(&stats.TotalQueries, 1)
	}
}

func printReport(duration time.Duration, stats *Stats) {
	qps := float64(stats.Success) / duration.Seconds()
	
	var totalLat time.Duration
	var latencies []time.Duration
	for l := range stats.Latencies {
		totalLat += l
		latencies = append(latencies, l)
	}

	avg := time.Duration(0)
	if len(latencies) > 0 {
		avg = totalLat / time.Duration(len(latencies))
	}

	fmt.Println("\n--- Scaling Test Results ---")
	fmt.Printf("Total Time:     %v\n", duration)
	fmt.Printf("Queries:        %d\n", stats.TotalQueries)
	fmt.Printf("Success:        %d\n", stats.Success)
	fmt.Printf("Errors:         %d\n", stats.Errors)
	fmt.Printf("Throughput:     %.2f QPS\n", qps)
	fmt.Printf("Average Latency: %v\n", avg)
	
	if stats.Errors > 0 {
		fmt.Printf("Error Rate:     %.2f%%\n", (float64(stats.Errors)/float64(stats.TotalQueries))*100)
	}
	fmt.Println("----------------------------")
}
