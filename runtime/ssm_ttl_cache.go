package runtime

import (
	"context"
	"sync"
	"time"
)

type ssmTTLCache struct {
	ssm   SSM
	ttl   time.Duration
	mu    sync.Mutex
	cache map[string]ssmTTLCacheEntry
}

type ssmTTLCacheEntry struct {
	val string
	exp time.Time
}

func NewSSMTTLCache(ssm SSM, ttl time.Duration) SSM {
	if ttl <= 0 {
		return ssm
	}
	return &ssmTTLCache{ssm: ssm, ttl: ttl, cache: map[string]ssmTTLCacheEntry{}}
}

func (s *ssmTTLCache) Set(ctx context.Context, key, val string, opts ...SSMSetOption) error {
	if err := s.ssm.Set(ctx, key, val, opts...); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.cache, key)
	s.mu.Unlock()
	return nil
}

func (s *ssmTTLCache) MustGet(ctx context.Context, key string) (string, error) {
	if val, ok := s.get(key); ok {
		return val, nil
	}
	val, err := s.ssm.MustGet(ctx, key)
	if err == nil {
		s.set(key, val)
	}
	return val, err
}

func (s *ssmTTLCache) MayGet(ctx context.Context, key string) (string, error) {
	if val, ok := s.get(key); ok {
		return val, nil
	}
	val, err := s.ssm.MayGet(ctx, key)
	if err == nil && val != "" {
		s.set(key, val)
	}
	return val, err
}

func (s *ssmTTLCache) ListParams(ctx context.Context, prefix string) ([]Param, error) {
	return s.ssm.ListParams(ctx, prefix)
}

func (s *ssmTTLCache) get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.cache[key]
	if !ok || time.Now().After(e.exp) {
		delete(s.cache, key)
		return "", false
	}
	return e.val, true
}

func (s *ssmTTLCache) set(key, val string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache[key] = ssmTTLCacheEntry{val: val, exp: time.Now().Add(s.ttl)}
}
