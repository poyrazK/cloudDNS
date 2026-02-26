package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// QueriesTotal tracks total DNS queries processed
	QueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clouddns_queries_total",
		Help: "Total number of DNS queries processed",
	}, []string{"qtype", "rcode", "protocol"})

	// QueryDuration tracks query processing time
	QueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "clouddns_query_duration_seconds",
		Help:    "Histogram of query processing duration",
		Buckets: prometheus.DefBuckets,
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
)
