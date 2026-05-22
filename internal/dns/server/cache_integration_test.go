package server

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/stretchr/testify/assert"
)

func TestCacheInvalidation_Integration(t *testing.T) {
	// 1. Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	// 2. Setup Server with Redis
	srv := NewServer("127.0.0.1:0", nil, nil)
	srv.Redis = NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 3. Start the invalidation listener in a goroutine
	go srv.startInvalidationListener(ctx, make(chan struct{}))
	
	// Give it a moment to subscribe
	time.Sleep(100 * time.Millisecond)

	// 4. Prime the L1 cache
	// Use "recursive:" prefix since no Repo is configured (no tenant context)
	name := "example.com."
	qtype := packet.A
	cacheKey := fmt.Sprintf("recursive:%s:%d", name, qtype)
	data := []byte("cached-data")
	srv.Cache.Set(cacheKey, data, 1*time.Hour)

	// Verify it's in L1
	_, found := srv.Cache.Get(cacheKey)
	assert.True(t, found, "Expected key to be in L1 cache")

	// 5. Trigger invalidation via Redis
	err = srv.Redis.Invalidate(ctx, "recursive", name, domain.TypeA)
	assert.NoError(t, err)

	// 6. Wait for async invalidation to propagate
	assert.Eventually(t, func() bool {
		_, found := srv.Cache.Get(cacheKey)
		return !found
	}, 2*time.Second, 50*time.Millisecond, "L1 cache was not invalidated after Redis event")
}

func TestCacheInvalidation_MalformedPayload(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	srv := NewServer("127.0.0.1:0", nil, nil)
	srv.Redis = NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.startInvalidationListener(ctx, make(chan struct{}))
	time.Sleep(100 * time.Millisecond)

	// Publish malformed payload directly to channel
	mr.Publish(InvalidationChannel, "malformed-payload-no-colon")
	
	// Server should just log a warning and not crash
	time.Sleep(100 * time.Millisecond)
}

func TestCacheInvalidation_ListenerDoneSignal(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	srv := NewServer("127.0.0.1:0", nil, nil)
	srv.Redis = NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.startInvalidationListener(ctx, done)
	}()

	// Give it a moment to subscribe
	time.Sleep(100 * time.Millisecond)

	// Close done - should trigger exit via case <-done:
	close(done)

	// Wait for goroutine to exit
	wgDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgDone)
	}()

	select {
	case <-wgDone:
		// Pass - exited via done signal
	case <-time.After(500 * time.Millisecond):
		t.Fatal("startInvalidationListener did not exit within 500ms after done close")
	}
}
