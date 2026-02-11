package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

type Stats struct {
	TotalQueries  uint64
	Success       uint64
	Errors        uint64
	BytesSent     uint64
	BytesReceived uint64
	Latencies     chan time.Duration
}

var tlds = []string{"com", "net", "org", "io", "dev", "ai", "cloud", "gov", "edu", "tr", "com.tr", "me", "info"}

func main() {
	target := flag.String("server", "127.0.0.1:1053", "DNS server to test")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	count := flag.Int("n", 1000, "Total number of queries to send")
	rangeLimit := flag.Int("range", 10000000, "Number of records in the database (default 10M)")
	zipfS := flag.Float64("zipf-s", 1.1, "Zipf distribution constant (s > 1). Higher means more 'Hot' domains.")
	zipfV := flag.Float64("zipf-v", 100, "Zipf distribution constant (v >= 1).")
	flag.Parse()

	fmt.Printf("Starting Realistic Scale Test\n")
	fmt.Printf("Configuration: %d queries | %d concurrency | Pool Size: %d | Zipf(s=%.1f, v=%.1f)\n", *count, *concurrency, *rangeLimit, *zipfS, *zipfV)

	stats := Stats{
		Latencies: make(chan time.Duration, *count),
	}

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(*concurrency)

	queriesPerWorker := *count / *concurrency

	for i := 0; i < *concurrency; i++ {
		go func(workerID int) {
			defer wg.Done()
			runRealisticWorker(*target, queriesPerWorker, workerID, uint64(*rangeLimit), *zipfS, *zipfV, &stats)
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)
	close(stats.Latencies)

	printEnhancedReport(duration, &stats, *concurrency)
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
		// Use Zipf distribution to select a 'Hot' or 'Cold' domain
		idx := zipf.Uint64()
		currentDomain := fmt.Sprintf("host-%d.%s", idx, tlds[idx%uint64(len(tlds))])

		p := packet.NewDnsPacket()
		p.Header.ID = uint16(r.Uint32())
		p.Questions = append(p.Questions, *packet.NewDnsQuestion(currentDomain, packet.A))

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
	fmt.Println("============================================\n")
}
