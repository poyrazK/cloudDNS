package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/poyrazK/cloudDNS/internal/dns/packet"
	"github.com/stretchr/testify/assert"
)

// TestCache_ConcurrencyHammer puts extreme concurrent stress on the L1 cache while
// L2 invalidation messages arrive unpredictably to ensure no data races or deadlocks occur.
func TestCache_ConcurrencyHammer(t *testing.T) {
	// Setup miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to run miniredis: %v", err)
	}
	defer mr.Close()

	// Setup Server with Redis
	srv := NewServer("127.0.0.1:0", nil, nil)
	srv.Redis = NewRedisCache(mr.Addr(), "", 0, RedisPoolConfig{})

	// Run for 3 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start invalidation listener
	go srv.startInvalidationListener(ctx, make(chan struct{}))
	// Give it a moment to subscribe
	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup

	key := fmt.Sprintf("hammer.test.:%d", packet.A)
	name := "hammer.test."
	qtype := domain.TypeA

	// Track operations for curiosity
	var readCount, writeCount, invalidationCount int64

	// 1000 Readers (The Hammer)
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					srv.Cache.Get(key)
					atomic.AddInt64(&readCount, 1)
					// Tiny sleep to avoid completely locking the CPU
					time.Sleep(1 * time.Microsecond)
				}
			}
		}()
	}

	// 10 Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("data-from-worker-%d", workerID))
			for {
				select {
				case <-ctx.Done():
					return
				default:
					srv.Cache.Set(key, data, 1*time.Minute)
					atomic.AddInt64(&writeCount, 1)
					time.Sleep(2 * time.Millisecond)
				}
			}
		}(i)
	}

	// 5 Invalidators (The Disruptor)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = srv.Redis.Invalidate(ctx, "test", name, qtype)
					atomic.AddInt64(&invalidationCount, 1)
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
	}

	// Background cache cleanup (The Janitor)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
				srv.Cache.Cleanup()
			}
		}
	}()

	// Wait for the context to timeout (3s) and all goroutines to finish
	wg.Wait()

	t.Logf("Hammer test complete. Reads: %d, Writes: %d, Invalidations: %d",
		atomic.LoadInt64(&readCount), atomic.LoadInt64(&writeCount), atomic.LoadInt64(&invalidationCount))

	// Ensure no race conditions occurred and the server is still alive
	assert.NotNil(t, srv.Cache)
}
