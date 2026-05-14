package nitriding

import (
	"sync"
	"time"
)

const (
	defaultItemExpiry = time.Minute
)

// Cache implements a simple cache whose items expire.
type Cache struct {
	sync.RWMutex
	Items map[string]time.Time
	TTL   time.Duration
}

// NewCache creates and returns a new cache with the given lifetime for cache
// items.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		Items: make(map[string]time.Time),
		TTL:   ttl,
	}
}

// Count returns the number of elements in the cache.
func (c *Cache) Count() int {
	c.RLock()
	defer c.RUnlock()

	return len(c.Items)
}

// pruneLater prunes the given element after ttl.
func (c *Cache) pruneLater(key string, ttl time.Duration) {
	time.Sleep(ttl)

	c.Lock()
	defer c.Unlock()
	delete(c.Items, key)
}

// Add adds a new string item to the cache.
func (c *Cache) Add(key string) {
	c.Lock()
	defer c.Unlock()

	c.Items[key] = time.Now().UTC()
	// Spawn a goroutine that deletes the given element after TTL.  Note that
	// the enclave's endpoint for requesting nonces should not be exposed to
	// the Internet because it would allow adversaries to request nonces at a
	// high rate, thus spawning many goroutines, which would constitute a
	// resource DoS attack.
	go c.pruneLater(key, c.TTL)
}

// Exists returns true if the given string item exists in the cache.  If the
// item exists but is expired, the function returns false.
func (c *Cache) Exists(key string) bool {
	c.RLock()
	defer c.RUnlock()
	_, exists := c.Items[key]

	return exists
}
