package server

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
// the background expiration cleanup loop.
func NewDNSCache() *DNSCache {
	c := &DNSCache{}
	for i := 0; i < shardCount; i++ {
		c.shards[i] = &cacheShard{
			items: make(map[string]cacheEntry),
		}
	}
	// Background goroutine to periodically clean up expired items from all shards.
	go c.cleanupLoop()
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
func (c *DNSCache) Get(key string) ([]byte, bool) {
	shard := c.getShard(key)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	item, found := shard.items[key]
	if !found {
		return nil, false
	}

	// Check if the item is still valid.
	if time.Now().After(item.expiresAt) {
		return nil, false
	}

	return item.data, true
}

// Set stores a response in the cache with a specific TTL.
func (c *DNSCache) Set(key string, data []byte, ttl time.Duration) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.items[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
}

// Flush removes all items from all shards in the cache.
func (c *DNSCache) Flush() {
	for i := 0; i < shardCount; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		shard.items = make(map[string]cacheEntry)
		shard.mu.Unlock()
	}
}

// cleanupLoop periodically triggers the cache-wide cleanup process.
func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.Cleanup()
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
