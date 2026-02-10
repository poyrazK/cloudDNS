package server

import (
	"sync"
	"time"
)

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

type DNSCache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
}

func NewDNSCache() *DNSCache {
	c := &DNSCache{
		items: make(map[string]cacheEntry),
	}
	// Background goroutine to clean up expired items
	go c.cleanupLoop()
	return c
}

func (c *DNSCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		return nil, false
	}

	if time.Now().After(item.expiresAt) {
		return nil, false
	}

	return item.data, true
}

func (c *DNSCache) Set(key string, data []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		for k, v := range c.items {
			if time.Now().After(v.expiresAt) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}
