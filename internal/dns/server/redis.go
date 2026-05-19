package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

// DLQChannel is the Redis list key for dead letter queue of failed invalidation messages.
const DLQChannel = "dns:invalidation:dlq"

// InvalidationChannel is the Redis pub/sub channel for cache invalidation events.
const InvalidationChannel = "dns:invalidation"

// RedisCache implements a DNS cache backed by Redis.
type RedisCache struct {
	client *redis.Client
}

// RedisPoolConfig holds connection pool settings for the Redis client.
type RedisPoolConfig struct {
	PoolSize       int
	MinIdleConns   int
	PoolTimeout    time.Duration
	ConnMaxLifetime time.Duration
}

// NewRedisCache creates a new Redis cache client.
func NewRedisCache(addr string, password string, db int, cfg RedisPoolConfig) *RedisCache {
	// Parse Redis URL if provided (e.g., redis://localhost:6379)
	if strings.HasPrefix(addr, "redis://") || strings.HasPrefix(addr, "rediss://") {
		if u, err := url.Parse(addr); err == nil {
			addr = u.Host
			if u.User != nil {
				password = u.User.Username()
			}
		}
	}

	if cfg.PoolSize == 0 {
		cfg.PoolSize = 100
	}
	if cfg.PoolTimeout == 0 {
		cfg.PoolTimeout = 4 * time.Second
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = 30 * time.Minute
	}
	if cfg.MinIdleConns == 0 {
		cfg.MinIdleConns = 10
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:            addr,
		Password:        password,
		DB:              db,
		PoolSize:        cfg.PoolSize,
		MinIdleConns:    cfg.MinIdleConns,
		PoolTimeout:     cfg.PoolTimeout,
		ConnMaxLifetime: cfg.ConnMaxLifetime,
	})
	return &RedisCache{client: rdb}
}

// Get retrieves a cached DNS response by key.
func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, bool) {
	val, err := r.client.Get(ctx, "dns:"+key).Bytes()
	if err != nil {
		return nil, false
	}
	return val, true
}

// GetWithTTL retrieves cached data and remaining TTL in a single pipeline call.
func (r *RedisCache) GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, bool) {
	pipe := r.client.Pipeline()
	getPipe := pipe.Get(ctx, "dns:"+key)
	ttlPipe := pipe.TTL(ctx, "dns:"+key)
	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, 0, false
	}
	val, err := getPipe.Bytes()
	if err != nil {
		return nil, 0, false
	}
	ttl := ttlPipe.Val()
	return val, ttl, true
}

// Set stores a DNS response in the cache with the given TTL.
func (r *RedisCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) {
	r.client.Set(ctx, "dns:"+key, data, ttl)
}

// Ping checks Redis connectivity.
func (r *RedisCache) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Invalidate deletes the key from Redis and publishes an invalidation event to all nodes.
// When qType is empty, publishes a zone-level invalidation (zone name only, no type suffix).
func (r *RedisCache) Invalidate(ctx context.Context, name string, qType domain.RecordType) error {
	key := "dns:" + name + ":" + string(qType)
	r.client.Del(ctx, key)
	var msg string
	if qType == "" {
		msg = name
	} else {
		msg = fmt.Sprintf("%s:%s", name, string(qType))
	}
	return r.client.Publish(ctx, InvalidationChannel, msg).Err()
}

// Subscribe returns a PubSub instance that receives invalidation keys.
func (r *RedisCache) Subscribe(ctx context.Context) *redis.PubSub {
	return r.client.Subscribe(ctx, InvalidationChannel)
}

// PushToDLQ pushes a failed invalidation message to the dead letter queue.
// The message is stored with a timestamp prefix for ordering.
func (r *RedisCache) PushToDLQ(ctx context.Context, msg string) error {
	dlqEntry := fmt.Sprintf("%d:%s", time.Now().UnixNano(), msg)
	return r.client.LPush(ctx, DLQChannel, dlqEntry).Err()
}

// PopFromDLQ pops a message from the dead letter queue with blocking.
// Returns ("", nil) if timeout is reached before a message is available.
func (r *RedisCache) PopFromDLQ(ctx context.Context, timeout time.Duration) (string, error) {
	result, err := r.client.BRPop(ctx, timeout, DLQChannel).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", err
	}
	if len(result) < 2 {
		return "", nil
	}
	if idx := strings.Index(result[1], ":"); idx >= 0 {
		return result[1][idx+1:], nil
	}
	return result[1], nil
}

// DLQLen returns the current length of the dead letter queue.
func (r *RedisCache) DLQLen(ctx context.Context) (int64, error) {
	return r.client.LLen(ctx, DLQChannel).Result()
}

// PoolConfig returns the pool configuration currently applied to the client.
func (r *RedisCache) PoolConfig() RedisPoolConfig {
	opts := r.client.Options()
	return RedisPoolConfig{
		PoolSize:       opts.PoolSize,
		MinIdleConns:   opts.MinIdleConns,
		PoolTimeout:    opts.PoolTimeout,
		ConnMaxLifetime: opts.ConnMaxLifetime,
	}
}

// Close shuts down the Redis client connection.
func (r *RedisCache) Close() error {
	return r.client.Close()
}
