// Package server provides the core DNS server implementation.
package server

import (
	"context"

	"github.com/poyrazK/cloudDNS/internal/dns/packet"
)

import (
	"hash/fnv"
	"sync"
	"time"
)

// shardCount determines the number of internal shards to reduce lock contention.
const shardCount = 256

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

type cacheShard struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
}

// DNSCache implements a sharded, thread-safe, in-memory cache for DNS responses.
// Sharding is used to minimize lock contention during high-concurrency access.
type DNSCache struct {
	shards [shardCount]*cacheShard
}

// NewDNSCache initializes a new DNSCache with pre-allocated shards and starts
// the background expiration cleanup loop. The done channel controls when the
// cleanup goroutine exits. If wg is provided, wg.Add(1) is called and wg.Done()
// is called when the cleanup goroutine exits.
func NewDNSCache(done <-chan struct{}, wg *sync.WaitGroup) *DNSCache {
	c := &DNSCache{}
	for i := 0; i < shardCount; i++ {
		c.shards[i] = &cacheShard{
			items: make(map[string]cacheEntry),
		}
	}
	if wg != nil {
		wg.Add(1)
	}
	go c.cleanupLoop(done, wg)
	return c
}

// getShard returns the specific cacheShard responsible for the given key based on its hash.
func (c *DNSCache) getShard(key string) *cacheShard {
	h := fnv.New32a()
	h.Write([]byte(key)) // #nosec G104
	return c.shards[h.Sum32()%shardCount]
}

// Get retrieves a response from the cache. It returns (nil, false) if the key is missing
// or has already expired.
// Note: callers must not retain or mutate the returned slice.
func (c *DNSCache) Get(key string) ([]byte, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	item, found := shard.items[key]
	if !found {
		return nil, false
	}

	if time.Now().After(item.expiresAt) {
		return nil, false
	}

	return item.data, true
}

// GetInto returns data from the cache with the transaction ID injected.
// For data >= 2 bytes: TXID is written at offset 0 (overwriting first 2 bytes of data).
// For data < 2 bytes: no TXID injection (would corrupt too-short responses).
// The returned slice is from a pooled buffer — callers must not retain or mutate it.
func (c *DNSCache) GetInto(key string, txID uint16) ([]byte, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	item, found := shard.items[key]
	if !found {
		return nil, false
	}

	if time.Now().After(item.expiresAt) {
		return nil, false
	}

	dataLen := len(item.data)

	// For data < 2 bytes, don't inject TXID (would corrupt the response)
	if dataLen < 2 {
		buf := packet.GetBuffer()
		if dataLen > packet.MaxPacketSize {
			packet.PutBuffer(buf)
			return nil, false
		}
		copy(buf.Buf, item.data)
		return buf.Buf[:dataLen], true
	}

	// dataLen >= 2: use pooled buffer, overwrite TXID at offset 0
	buf := packet.GetBuffer()
	if dataLen > packet.MaxPacketSize {
		packet.PutBuffer(buf)
		return nil, false
	}

	// Copy cached data into pooled buffer
	copy(buf.Buf, item.data)
	// Overwrite TXID at offset 0 (same as original behavior, but via pooled buffer)
	buf.Buf[0] = byte(txID >> 8)
	buf.Buf[1] = byte(txID & 0xFF)
	return buf.Buf[:dataLen], true
}

// SetNoCopy stores data directly without copying. The caller must not
// retain or mutate the passed slice after calling this method. Intended
// for data that is already an independent heap copy (e.g., from Redis).
func (c *DNSCache) SetNoCopy(key string, data []byte, ttl time.Duration) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.items[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
}

// Set stores a response in the cache with a specific TTL.
// The input data is copied so the cache owns its own backing array.
func (c *DNSCache) Set(key string, data []byte, ttl time.Duration) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Copy the data so the caller can mutate their slice without affecting the cache
	copied := make([]byte, len(data))
	copy(copied, data)

	shard.items[key] = cacheEntry{
		data:      copied,
		expiresAt: time.Now().Add(ttl),
	}
}

// Invalidate removes a specific key from the cache.
func (c *DNSCache) Invalidate(key string) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delete(shard.items, key)
}

// Ping verifies the cache is responsive by checking the context.
func (c *DNSCache) Ping(ctx context.Context) error {
	return ctx.Err()
}

// Flush clears all entries from the DNS cache.
func (c *DNSCache) Flush() {
	for i := 0; i < shardCount; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		shard.items = make(map[string]cacheEntry)
		shard.mu.Unlock()
	}
}

// cleanupLoop periodically triggers the cache-wide cleanup process.
// It exits when done is closed.
func (c *DNSCache) cleanupLoop(done <-chan struct{}, wg *sync.WaitGroup) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	if wg != nil {
		defer wg.Done()
	}
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			c.Cleanup()
		}
	}
}

// Cleanup scans all shards and deletes items that have passed their expiration time.
func (c *DNSCache) Cleanup() {
	now := time.Now()
	for i := 0; i < shardCount; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		for k, v := range shard.items {
			if now.After(v.expiresAt) {
				delete(shard.items, k)
			}
		}
		shard.mu.Unlock()
	}
}
