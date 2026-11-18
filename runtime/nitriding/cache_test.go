package nitriding

import (
	"fmt"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	c := NewCache(time.Millisecond * 50)
	elem := "foo"

	c.Add(elem)
	if !c.Exists(elem) {
		t.Errorf("Expected element not found in cache.")
	}

	// Wait until the element expired.
	time.Sleep(time.Millisecond * 100)
	if c.Exists(elem) {
		t.Errorf("Element in cache despite being expired.")
	}

	// Now ask for a non-existing item.
	if c.Exists("bar") {
		t.Errorf("Non-existing element is supposed to exist.")
	}
}

// TestCacheExistsChecksExpiry verifies that expiry is decided from the stored
// timestamp, not only by the pruning goroutine. A delayed prune must not make
// an already expired item look present.
func TestCacheExistsChecksExpiry(t *testing.T) {
	c := NewCache(time.Minute)

	c.Add("expired")
	c.Items["expired"] = time.Now().UTC().Add(-2 * c.TTL)
	if c.Exists("expired") {
		t.Fatal("expected an expired item to be absent")
	}

	c.Add("fresh")
	if !c.Exists("fresh") {
		t.Fatal("expected a fresh item to be present")
	}
}

func TestCacheWithManyElems(t *testing.T) {
	c := NewCache(time.Millisecond * 50)

	// Add 100 items.
	for i := 0; i < 100; i++ {
		c.Add(fmt.Sprintf("%d", i))
	}

	// Wait for those 100 items to expire.
	time.Sleep(time.Millisecond * 100)

	// Add another 100 items.
	for i := 100; i < 200; i++ {
		c.Add(fmt.Sprintf("%d", i))
	}

	// We now expect 100 items to remain in the cache.
	count := c.Count()
	if count != 100 {
		t.Fatalf("Expected 100 but got %d elems in cache.", count)
	}
}
