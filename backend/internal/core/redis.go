package core

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrCacheFull = errors.New("in-memory cache is full")

// CacheClient abstrae Redis / memoria. Las operaciones que forman parte de decisiones de
// seguridad (deduplicado, rate limit) son ATOMICAS: SetNX e IncrWithTTL.
type CacheClient interface {
	Set(ctx context.Context, key string, val string, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Exists(ctx context.Context, key string) (bool, error)
	Incr(ctx context.Context, key string) (int64, error)
	// IncrWithTTL incrementa y, si la clave es nueva, le fija el TTL, todo en una operacion atomica.
	IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// SetNX guarda la clave solo si no existia. Devuelve true si la adquirio.
	SetNX(ctx context.Context, key string, val string, expiration time.Duration) (bool, error)
}

// ---- Redis ---------------------------------------------------------------------------------

type RedisWrapper struct{ client *redis.Client }

var incrTTLScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return c`)

func (r *RedisWrapper) Set(ctx context.Context, key string, val string, exp time.Duration) error {
	return r.client.Set(ctx, key, val, exp).Err()
}
func (r *RedisWrapper) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}
func (r *RedisWrapper) Exists(ctx context.Context, key string) (bool, error) {
	n, err := r.client.Exists(ctx, key).Result()
	return n > 0, err
}
func (r *RedisWrapper) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}
func (r *RedisWrapper) IncrWithTTL(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return incrTTLScript.Run(ctx, r.client, []string{key}, ttl.Milliseconds()).Int64()
}
func (r *RedisWrapper) SetNX(ctx context.Context, key string, val string, exp time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, val, exp).Result()
}

// ---- Memoria -------------------------------------------------------------------------------

type memoryItem struct {
	val       string
	expiresAt time.Time
}

const memoryMaxItems = 200_000

type MemoryCache struct {
	mu      sync.Mutex
	items   map[string]memoryItem
	stop    chan struct{}
	once    sync.Once
	maxSize int
}

func NewMemoryCache() *MemoryCache {
	mc := &MemoryCache{items: make(map[string]memoryItem), stop: make(chan struct{}), maxSize: memoryMaxItems}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-mc.stop:
				return
			case <-ticker.C:
				mc.mu.Lock()
				mc.sweepLocked(time.Now())
				mc.mu.Unlock()
			}
		}
	}()
	return mc
}

func (m *MemoryCache) Close() { m.once.Do(func() { close(m.stop) }) }

func (m *MemoryCache) sweepLocked(now time.Time) {
	for k, v := range m.items {
		if !v.expiresAt.IsZero() && now.After(v.expiresAt) {
			delete(m.items, k)
		}
	}
}

func (m *MemoryCache) liveLocked(key string, now time.Time) (memoryItem, bool) {
	it, ok := m.items[key]
	if !ok || (!it.expiresAt.IsZero() && now.After(it.expiresAt)) {
		return memoryItem{}, false
	}
	return it, true
}

// reserveLocked comprueba capacidad antes de crear una clave nueva (defensa frente a claves ilimitadas).
func (m *MemoryCache) reserveLocked(now time.Time) error {
	if len(m.items) < m.maxSize {
		return nil
	}
	m.sweepLocked(now)
	if len(m.items) >= m.maxSize {
		return ErrCacheFull
	}
	return nil
}

func expiry(now time.Time, d time.Duration) time.Time {
	if d > 0 {
		return now.Add(d)
	}
	return time.Time{}
}

func (m *MemoryCache) Set(_ context.Context, key string, val string, exp time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if _, ok := m.items[key]; !ok {
		if err := m.reserveLocked(now); err != nil {
			return err
		}
	}
	m.items[key] = memoryItem{val: val, expiresAt: expiry(now, exp)}
	return nil
}

func (m *MemoryCache) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.liveLocked(key, time.Now())
	if !ok {
		return "", redis.Nil
	}
	return it.val, nil
}

func (m *MemoryCache) Exists(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.liveLocked(key, time.Now())
	return ok, nil
}

func (m *MemoryCache) Incr(ctx context.Context, key string) (int64, error) {
	return m.IncrWithTTL(ctx, key, 0)
}

func (m *MemoryCache) IncrWithTTL(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if it, ok := m.liveLocked(key, now); ok {
		n, _ := strconv.ParseInt(it.val, 10, 64)
		n++
		m.items[key] = memoryItem{val: strconv.FormatInt(n, 10), expiresAt: it.expiresAt}
		return n, nil
	}
	if err := m.reserveLocked(now); err != nil {
		return 0, err
	}
	m.items[key] = memoryItem{val: "1", expiresAt: expiry(now, ttl)}
	return 1, nil
}

func (m *MemoryCache) SetNX(_ context.Context, key string, val string, exp time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if _, ok := m.liveLocked(key, now); ok {
		return false, nil
	}
	if err := m.reserveLocked(now); err != nil {
		return false, err
	}
	m.items[key] = memoryItem{val: val, expiresAt: expiry(now, exp)}
	return true, nil
}

func InitRedisOrMemory(cfg *Config) CacheClient {
	if cfg.RedisAddr != "" {
		client := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := client.Ping(ctx).Err(); err == nil {
			slog.Info("connected to redis", "addr", cfg.RedisAddr)
			return &RedisWrapper{client: client}
		}
		slog.Warn("failed to ping redis, falling back to memory cache (dedup / rate-limit will be per-instance)", "addr", cfg.RedisAddr)
	}
	slog.Info("using in-memory cache / dedup store")
	return NewMemoryCache()
}
