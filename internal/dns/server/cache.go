package server

import (
	"hash/fnv"
	"sync"
	"time"
)

const shardCount = 256

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

type cacheShard struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
}

type DNSCache struct {
	shards [shardCount]*cacheShard
}

func NewDNSCache() *DNSCache {
	c := &DNSCache{}
	for i := 0; i < shardCount; i++ {
		c.shards[i] = &cacheShard{
			items: make(map[string]cacheEntry),
		}
	}
	// Background goroutine to clean up expired items
	go c.cleanupLoop()
	return c
}

func (c *DNSCache) getShard(key string) *cacheShard {
	h := fnv.New32a()
	h.Write([]byte(key)) // #nosec G104
	return c.shards[h.Sum32()%shardCount]
}

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

func (c *DNSCache) Set(key string, data []byte, ttl time.Duration) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.items[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *DNSCache) Flush() {
	for i := 0; i < shardCount; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		shard.items = make(map[string]cacheEntry)
		shard.mu.Unlock()
	}
}

func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
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
}
