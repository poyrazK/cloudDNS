package server

import (
	"net"
	"sync"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

// cacheLockShardCount is the number of shards for per-key cache locks.
// Using sharded locking avoids unbounded map growth while providing per-key granularity.
const cacheLockShardCount = 256

type cacheLockShard struct {
	mu sync.Mutex
}

func (s *cacheLockShard) Lock()   { s.mu.Lock() }
func (s *cacheLockShard) Unlock() { s.mu.Unlock() }

type cacheLockTable [cacheLockShardCount]cacheLockShard

var globalCacheLocks cacheLockTable

// TsigKey holds a TSIG key's secret and authorized tenant ID.
type TsigKey struct {
	Secret   []byte
	TenantID string
}

// inflightEntry holds state for an in-progress L2 cache fetch.
// The done channel is closed by the fetching goroutine when it finishes,
// unblocking all goroutines that were waiting on it.
type inflightEntry struct {
	done chan struct{}
}

type udpTask struct {
	addr net.Addr
	data []byte
	conn net.PacketConn
}

// queryDBResult holds the results of a DB query for use with singleflight.
type queryDBResult struct {
	zone    *domain.Zone
	records []domain.Record
	err     error
}

type updateError struct {
	rcode int
	msg   string
}

func (e updateError) Error() string { return e.msg }

type hashEntry struct {
	name string
	hash []byte
}