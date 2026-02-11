package server

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

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
