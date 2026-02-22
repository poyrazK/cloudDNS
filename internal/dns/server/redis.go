package server

import (
	"context"
	"fmt"
	"time"

	"github.com/poyrazK/cloudDNS/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

const InvalidationChannel = "dns:invalidation"

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr string, password string, db int) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &RedisCache{client: rdb}
}

func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, bool) {
	val, err := r.client.Get(ctx, "dns:"+key).Bytes()
	if err != nil {
		return nil, false
	}
	return val, true
}

func (r *RedisCache) Set(ctx context.Context, key string, data []byte, ttl time.Duration) {
	r.client.Set(ctx, "dns:"+key, data, ttl)
}

func (r *RedisCache) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Invalidate publishes an invalidation event to all nodes.
func (r *RedisCache) Invalidate(ctx context.Context, name string, qType domain.RecordType) error {
	msg := fmt.Sprintf("%s:%s", name, string(qType))
	return r.client.Publish(ctx, InvalidationChannel, msg).Err()
}

// Subscribe returns a channel that receives invalidation keys.
func (r *RedisCache) Subscribe(ctx context.Context) <-chan *redis.Message {
	pubsub := r.client.Subscribe(ctx, InvalidationChannel)
	return pubsub.Channel()
}
