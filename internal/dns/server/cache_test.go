package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
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
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
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
	done := make(chan struct{})
	// No cleanup needed - test runs briefly
	cache := NewDNSCache(done, nil)

	// Simple smoke test for concurrent access
	for i := 0; i < 100; i++ {
		go func(n int) {
			cache.Set("key", []byte{byte(n)}, 1*time.Hour)
			cache.Get("key")
		}(i)
	}
}

func TestCacheCleanup(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
	cache.Set("keep", []byte{1}, 1*time.Hour)
	cache.Set("drop", []byte{2}, -1*time.Hour) // Already expired

	cache.Cleanup()

	_, foundKeep := cache.Get("keep")
	if !foundKeep {
		t.Errorf("Expected to keep 'keep' key")
	}
}

func TestCacheFlush(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
	cache.Set("a", []byte{1}, 1*time.Hour)
	cache.Flush()

	_, found := cache.Get("a")
	if found {
		t.Errorf("Expected cache to be empty after flush")
	}
}

func TestCacheInvalidate(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
	cache.Set("key1", []byte{1}, 1*time.Hour)
	cache.Invalidate("key1")
	
	_, found := cache.Get("key1")
	if found {
		t.Error("key should be invalidated")
	}
}

func TestCacheGetReturnsInternalSlice(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
	key := "copy-test.com:1"
	originalData := []byte{1, 2, 3, 4}
	cache.Set(key, originalData, 1*time.Hour)

	// Get the data from cache
	res, found := cache.Get(key)
	if !found {
		t.Fatalf("Expected to find key %s", key)
	}

	// Mutate the returned slice — this reflects the new zero-copy behavior
	res[0] = 0xFF
	res[1] = 0xFF

	// Get again — data should be mutated since Get() returns the internal slice
	res2, found := cache.Get(key)
	if !found {
		t.Fatalf("Expected to find key %s on second call", key)
	}
	if res2[0] != 0xFF || res2[1] != 0xFF {
		t.Errorf("Expected res2 to reflect mutation, got %v", res2)
	}

	// Verify the caller's original data was not affected (Set() made a copy)
	if originalData[0] != 1 || originalData[1] != 2 {
		t.Errorf("Caller's original data was mutated by Set()")
	}
}

func TestCachePing(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	cache := NewDNSCache(done, nil)
	
	// 1. Success case
	if err := cache.Ping(context.Background()); err != nil {
		t.Errorf("Ping failed: %v", err)
	}

	// 2. Canceled context case
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cache.Ping(ctx); err == nil {
		t.Error("Expected error for canceled context, got nil")
	} else if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}
