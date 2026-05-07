// Package metrics provides Prometheus metrics collection and
// exposition for DNS server monitoring.
package metrics

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// DNSBuckets are appropriate for DNS query latencies ranging from
// sub-millisecond (local cache) to seconds (AXFR/recursive lookups).
var DNSBuckets = []float64{
	0.00005,  // 50µs   — L1 cache hit
	0.0001,   // 100µs  — L2 cache hit
	0.00025,  // 250µs  — fast DB
	0.0005,   // 500µs  — typical DB
	0.001,    // 1ms
	0.0025,   // 2.5ms
	0.005,    // 5ms
	0.01,     // 10ms   — network latency
	0.025,    // 25ms
	0.05,     // 50ms   — slow network
	0.1,      // 100ms
	0.25,     // 250ms
	0.5,      // 500ms
	1.0,      // 1s
	2.5,      // 2.5s   — AXFR timeout
	5.0,      // 5s
	10.0,     // 10s    — slow AXFR
}

var (
	// QueriesTotal tracks total DNS queries processed
	QueriesTotal *prometheus.CounterVec
	// QueryDuration tracks query processing time
	QueryDuration *prometheus.HistogramVec
	// CacheOperations tracks L1/L2 cache hits and misses
	CacheOperations *prometheus.CounterVec
	// ActiveWorkers tracks number of busy UDP workers
	ActiveWorkers prometheus.Gauge
	// DBConnectionsActive tracks open database connections
	DBConnectionsActive prometheus.Gauge
	// BGPAnnounced indicates if the node is currently announcing routes via BGP
	BGPAnnounced prometheus.Gauge

	// CacheHitRatio tracks the L1 cache hit ratio (computed periodically)
	CacheHitRatio prometheus.Gauge
	// CacheHitCount and CacheMissCount track raw counts for ratio computation
	CacheHitCount  uint64
	CacheMissCount uint64

	// DNSSECKeysTotal tracks DNSSEC keys by zone, key type, and algorithm
	DNSSECKeysTotal *prometheus.GaugeVec
	// DNSSECKeysAgeSeconds tracks age of active signing keys
	DNSSECKeysAgeSeconds *prometheus.GaugeVec
	// DNSSECZonesSigned tracks number of zones with DNSSEC active
	DNSSECZonesSigned prometheus.Gauge

	// NotifiesTotal tracks incoming NOTIFY requests
	NotifiesTotal *prometheus.CounterVec
	// RateLimitedTotal tracks queries rejected by rate limiter
	RateLimitedTotal prometheus.Counter
	// AXFRBytesTotal tracks bytes transferred via zone transfers
	AXFRBytesTotal prometheus.Counter
	// RecursiveResolutionsTotal tracks recursive resolution outcomes
	RecursiveResolutionsTotal *prometheus.CounterVec

	// ZonesTotal tracks total hosted zones
	ZonesTotal prometheus.Gauge
	// RecordsTotal tracks total records across all zones
	RecordsTotal prometheus.Gauge
)

// DerivedMetricCollector periodically computes derived metrics (e.g., cache hit ratio)
// to avoid per-query overhead.
type DerivedMetricCollector struct {
	interval time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewDerivedMetricCollector creates a collector that updates derived metrics at the given interval.
func NewDerivedMetricCollector(interval time.Duration) *DerivedMetricCollector {
	c := &DerivedMetricCollector{
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go c.run()
	return c
}

func (c *DerivedMetricCollector) run() {
	defer close(c.doneCh)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.compute()
		}
	}
}

func (c *DerivedMetricCollector) compute() {
	hits := atomic.LoadUint64(&CacheHitCount)
	misses := atomic.LoadUint64(&CacheMissCount)
	total := hits + misses
	if total > 0 {
		CacheHitRatio.Set(float64(hits) / float64(total))
	}
}

// Stop gracefully stops the collector goroutine.
func (c *DerivedMetricCollector) Stop() {
	close(c.stopCh)
	<-c.doneCh
}

// RecordCacheHit records a cache hit for derived metric computation.
// Thread-safe via atomic operations.
func RecordCacheHit() {
	atomic.AddUint64(&CacheHitCount, 1)
}

// RecordCacheMiss records a cache miss for derived metric computation.
// Thread-safe via atomic operations.
func RecordCacheMiss() {
	atomic.AddUint64(&CacheMissCount, 1)
}

func init() {
	// QueriesTotal tracks total DNS queries processed
	QueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clouddns_queries_total",
		Help: "Total number of DNS queries processed",
	}, []string{"qtype", "rcode", "protocol"})

	// QueryDuration tracks query processing time (now with DNS-appropriate buckets)
	QueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "clouddns_query_duration_seconds",
		Help:    "Histogram of query processing duration",
		Buckets: DNSBuckets,
	}, []string{"source"})

	// CacheOperations tracks L1/L2 cache hits and misses
	CacheOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clouddns_cache_operations_total",
		Help: "Total number of cache hits and misses",
	}, []string{"level", "result"})

	// ActiveWorkers tracks number of busy UDP workers
	ActiveWorkers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_active_workers",
		Help: "Number of active workers in the UDP pool",
	})

	// DBConnectionsActive tracks open database connections
	DBConnectionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_db_connections_active",
		Help: "Number of active database connections",
	})

	// BGPAnnounced indicates if the node is currently announcing routes via BGP
	BGPAnnounced = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_bgp_announced",
		Help: "Binary indicator of BGP announcement status (1 = announcing, 0 = withdrawn)",
	})

	// CacheHitRatio tracks the computed cache hit ratio
	CacheHitRatio = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_cache_hit_ratio",
		Help: "L1 cache hit ratio (hits / total cache operations), computed every 30s",
	})

	// DNSSECKeysTotal tracks DNSSEC keys by zone, key type, and algorithm
	DNSSECKeysTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "clouddns_dnssec_keys_total",
		Help: "Total number of active DNSSEC keys",
	}, []string{"zone", "key_type", "algorithm"})

	// DNSSECKeysAgeSeconds tracks age of active signing keys
	DNSSECKeysAgeSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "clouddns_dnssec_keys_age_seconds",
		Help: "Age of active DNSSEC signing keys in seconds",
	}, []string{"zone", "key_type"})

	// DNSSECZonesSigned tracks number of zones with DNSSEC active
	DNSSECZonesSigned = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_zones_signed",
		Help: "Number of zones with DNSSEC enabled and active",
	})

	// NotifiesTotal tracks incoming NOTIFY requests
	NotifiesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clouddns_notifies_total",
		Help: "Total number of NOTIFY messages received",
	}, []string{"zone", "result"})

	// RateLimitedTotal tracks queries rejected by rate limiter
	RateLimitedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clouddns_rate_limited_total",
		Help: "Total number of queries rejected by rate limiter",
	})

	// AXFRBytesTotal tracks bytes transferred via zone transfers
	AXFRBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clouddns_axfr_bytes_total",
		Help: "Total bytes transferred via AXFR/IXFR",
	})

	// RecursiveResolutionsTotal tracks recursive resolution outcomes
	RecursiveResolutionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clouddns_recursive_resolutions_total",
		Help: "Total number of recursive resolution outcomes",
	}, []string{"result"})

	// ZonesTotal tracks total hosted zones
	ZonesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_zones_total",
		Help: "Total number of hosted zones",
	})

	// RecordsTotal tracks total records across all zones
	RecordsTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clouddns_records_total",
		Help: "Total number of records across all zones",
	})
}

// ZoneRecordCounter provides a way to update zone/record count metrics periodically.
type ZoneRecordCounter struct {
	repo     ZoneRecordRepo
	interval time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	wg       sync.WaitGroup
}

// ZoneRecordRepo is the interface for fetching zone and record counts.
type ZoneRecordRepo interface {
	ListZones(ctx context.Context, tenantID string) ([]domain.Zone, error)
	ListRecordsForZone(ctx context.Context, zoneID string, tenantID string) ([]domain.Record, error)
}

// NewZoneRecordCounter creates a counter that updates zone/record metrics periodically.
func NewZoneRecordCounter(repo ZoneRecordRepo, interval time.Duration) *ZoneRecordCounter {
	return &ZoneRecordCounter{
		repo:     repo,
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start begins the periodic collection goroutine.
func (c *ZoneRecordCounter) Start() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		// Run once immediately
		c.collect()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.collect()
			}
		}
	}()
}

// Stop gracefully stops the collector.
func (c *ZoneRecordCounter) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	close(c.doneCh)
}

func (c *ZoneRecordCounter) collect() {
	ctx := context.Background()
	zones, err := c.repo.ListZones(ctx, "")
	if err == nil {
		ZonesTotal.Set(float64(len(zones)))
	}
}