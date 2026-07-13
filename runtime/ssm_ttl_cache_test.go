package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSSMTTLCacheMustGet(t *testing.T) {
	ctx := context.Background()

	t.Run("disabled", func(t *testing.T) {
		fake := &fakeSSM{params: map[string]string{"/key": "one"}}
		ssm := NewSSMTTLCache(NewSSM(fake), 0)

		got, err := ssm.MustGet(ctx, "/key")
		require.NoError(t, err)
		if got != "one" {
			t.Fatalf("got %q, want %q", got, "one")
		}

		fake.params["/key"] = "two"
		got, err = ssm.MustGet(ctx, "/key")
		require.NoError(t, err)
		if got != "two" {
			t.Fatalf("got %q, want %q", got, "two")
		}
		if len(fake.calls) != 2 {
			t.Fatalf("got %d SSM calls, want 2", len(fake.calls))
		}
	})

	t.Run("caches until ttl", func(t *testing.T) {
		fake := &fakeSSM{params: map[string]string{"/key": "one"}}
		ssm := NewSSMTTLCache(NewSSM(fake), 20*time.Millisecond)

		got, err := ssm.MustGet(ctx, "/key")
		require.NoError(t, err)
		if got != "one" {
			t.Fatalf("got %q, want %q", got, "one")
		}

		fake.params["/key"] = "two"
		got, err = ssm.MustGet(ctx, "/key")
		require.NoError(t, err)
		if got != "one" {
			t.Fatalf("got %q, want cached %q", got, "one")
		}
		if len(fake.calls) != 1 {
			t.Fatalf("got %d SSM calls, want 1", len(fake.calls))
		}

		time.Sleep(30 * time.Millisecond)
		got, err = ssm.MustGet(ctx, "/key")
		require.NoError(t, err)
		if got != "two" {
			t.Fatalf("got %q, want %q", got, "two")
		}
		if len(fake.calls) != 2 {
			t.Fatalf("got %d SSM calls, want 2", len(fake.calls))
		}
	})
}

func TestSSMTTLCacheMayGetDoesNotCacheEmpty(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSSM{params: map[string]string{}}
	ssm := NewSSMTTLCache(NewSSM(fake), time.Hour)

	got, err := ssm.MayGet(ctx, "/key")
	require.NoError(t, err)
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}

	fake.params["/key"] = "value"
	got, err = ssm.MayGet(ctx, "/key")
	require.NoError(t, err)
	if got != "value" {
		t.Fatalf("got %q, want %q", got, "value")
	}
	if len(fake.calls) != 2 {
		t.Fatalf("got %d SSM calls, want 2", len(fake.calls))
	}
}

func TestSSMTTLCacheSetInvalidatesCache(t *testing.T) {
	ctx := context.Background()
	fake := &fakeSSM{params: map[string]string{"/key": "one"}}
	ssm := NewSSMTTLCache(NewSSM(fake), time.Hour)

	got, err := ssm.MustGet(ctx, "/key")
	require.NoError(t, err)
	if got != "one" {
		t.Fatalf("got %q, want %q", got, "one")
	}

	require.NoError(t, ssm.Set(ctx, "/key", "two"))
	got, err = ssm.MustGet(ctx, "/key")
	require.NoError(t, err)
	if got != "two" {
		t.Fatalf("got %q, want %q", got, "two")
	}
}
