package server

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisCache(t *testing.T) {
	// 1. Setup miniredis
	mr, err := miniredis.Run()
	if errScan != nil {
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
}
