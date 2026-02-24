package server

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
)

func TestRedisCache(t *testing.T) {
	// 1. Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	// 2. Initialize RedisCache
	cache := NewRedisCache(mr.Addr(), "", 0)
	ctx := context.Background()

	// 3. Test Set and Get
	key := "test.key."
	data := []byte{1, 2, 3, 4}
	ttl := 10 * time.Second

	cache.Set(ctx, key, data, ttl)

	val, found := cache.Get(ctx, key)
	if !found {
		t.Errorf("Expected key to be found in Redis")
	}
	if string(val) != string(data) {
		t.Errorf("Expected %v, got %v", data, val)
	}

	// 4. Test Get Missing Key
	_, found = cache.Get(ctx, "nonexistent")
	if found {
		t.Errorf("Expected nonexistent key to not be found")
	}

	// 5. Test Invalidate
	err = cache.Invalidate(ctx, "test.key.", domain.TypeA)
	if err != nil {
		t.Errorf("Invalidate failed: %v", err)
	}
	// Note: Invalidate in RedisCache only publishes to Pub/Sub, 
	// it doesn't delete the key from Redis itself (L3 is common).
	// Actually, the implementation should probably delete it too.
}

func TestRedisCache_Ping(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	cache := NewRedisCache(mr.Addr(), "", 0)
	if err := cache.Ping(context.Background()); err != nil {
		t.Errorf("Ping failed: %v", err)
	}
}

func TestRedisCache_Subscribe(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	cache := NewRedisCache(mr.Addr(), "", 0)
	ch := cache.Subscribe(context.Background())
	if ch == nil {
		t.Error("Subscribe returned nil channel")
	}
}
