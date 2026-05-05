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
}

func TestRedisCache_GetWithTTL(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	cache := NewRedisCache(mr.Addr(), "", 0)
	ctx := context.Background()

	key := "get-with-ttl.test."
	data := []byte{1, 2, 3}
	cache.Set(ctx, key, data, 10*time.Second)

	val, ttl, found := cache.GetWithTTL(ctx, key)
	if !found {
		t.Fatalf("Expected key to be found")
	}
	if string(val) != string(data) {
		t.Errorf("Data mismatch: got %v, want %v", val, data)
	}
	if ttl <= 0 {
		t.Errorf("Expected positive TTL, got %v", ttl)
	}

	// After expiration, key should not be found
	mr.FastForward(11 * time.Second)
	_, _, found = cache.GetWithTTL(ctx, key)
	if found {
		t.Errorf("Expected key to be expired")
	}
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

func TestRedisCache_PopFromDLQ(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	rdb := NewRedisCache(mr.Addr(), "", 0)
	ctx := context.Background()

	// Test timeout case
	msg, err := rdb.PopFromDLQ(ctx, 100*time.Millisecond)
	if msg != "" || err != nil {
		t.Errorf("Expected empty msg on timeout, got %q, err=%v", msg, err)
	}

	// Test successful pop
	rdb.PushToDLQ(ctx, "test-msg")
	msg, err = rdb.PopFromDLQ(ctx, time.Second)
	if msg != "test-msg" || err != nil {
		t.Errorf("Expected 'test-msg', got %q, err=%v", msg, err)
	}
}

func TestRedisCache_DLQLen(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	rdb := NewRedisCache(mr.Addr(), "", 0)
	ctx := context.Background()

	// Empty DLQ
	n, err := rdb.DLQLen(ctx)
	if n != 0 || err != nil {
		t.Errorf("Expected 0, got %d, err=%v", n, err)
	}

	// Add items
	rdb.PushToDLQ(ctx, "msg1")
	rdb.PushToDLQ(ctx, "msg2")
	n, err = rdb.DLQLen(ctx)
	if n != 2 || err != nil {
		t.Errorf("Expected 2, got %d, err=%v", n, err)
	}
}

func TestRedisCache_Close(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	// Don't defer mr.Close() — Close should handle it
	cache := NewRedisCache(mr.Addr(), "", 0)
	if err := cache.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
	// After close, Ping should fail
	if err := cache.Ping(context.Background()); err == nil {
		t.Errorf("Expected Ping to fail after Close")
	}
}
