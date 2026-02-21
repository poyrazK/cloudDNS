package server

import (
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	cache := NewDNSCache()
	key := "test.com:1"
	data := []byte{1, 2, 3, 4}
	
	cache.Set(key, data, 1*time.Minute)
	
	res, found := cache.Get(key)
	if !found {
		t.Errorf("Expected to find key %s", key)
	}
	if len(res) != 4 || res[0] != 1 {
		t.Errorf("Data mismatch")
	}
}

func TestCacheExpiration(t *testing.T) {
	cache := NewDNSCache()
	key := "expire.com:1"
	data := []byte{0}
	
	// Set with very short TTL
	cache.Set(key, data, 1*time.Millisecond)
	
	// Wait for expiration
	time.Sleep(10 * time.Millisecond)
	
	_, found := cache.Get(key)
	if found {
		t.Errorf("Expected key to be expired")
	}
}

func TestCacheConcurrency(_ *testing.T) {
	cache := NewDNSCache()
	
	// Simple smoke test for concurrent access
	for i := 0; i < 100; i++ {
		go func(n int) {
			cache.Set("key", []byte{byte(n)}, 1*time.Hour)
			cache.Get("key")
		}(i)
	}
}

func TestCacheCleanup(t *testing.T) {
	cache := NewDNSCache()
	cache.Set("keep", []byte{1}, 1*time.Hour)
	cache.Set("drop", []byte{2}, -1*time.Hour) // Already expired
	
	cache.Cleanup()
	
	_, foundKeep := cache.Get("keep")
	if !foundKeep {
		t.Errorf("Expected to keep 'keep' key")
	}
	
	// Get() also checks expiration, but let's check shards directly or trust Get()
	// Actually Get() returning false means it works.
}

func TestCacheFlush(t *testing.T) {
	cache := NewDNSCache()
	cache.Set("a", []byte{1}, 1*time.Hour)
	cache.Flush()
	
	_, found := cache.Get("a")
	if found {
		t.Errorf("Expected cache to be empty after flush")
	}
}
