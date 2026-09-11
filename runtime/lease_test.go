package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testLeaseBucket = "test-bucket"

func setLeaseTestEnv(t *testing.T) {
	t.Helper()
}

// writeLeaseDoc injects a lease object directly, as a peer enclave would have.
func writeLeaseDoc(t *testing.T, s3 *fakeS3, key string, expiresAt time.Time) {
	t.Helper()
	body, err := json.Marshal(leaseDocV1{
		AcquiredAt: expiresAt.Add(-leaseTTL).Unix(),
		ExpiresAt:  expiresAt.Unix(),
	})
	require.NoError(t, err)
	s3.putRawObject(key, body)
}

func TestLeaseAcquireUncontended(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, lease)

	key := leaseObjectKey(testCfg, "genesis")
	require.Equal(t, "prod/app/lock/genesis", key)
	require.NotEmpty(t, s3.currentETag(key))
	require.NoError(t, lease.Context().Err())

	require.NoError(t, lease.Release(ctx))
	require.Empty(t, s3.currentETag(key), "release must drop the object")
	require.ErrorIs(t, context.Cause(lease.Context()), errLeaseReleased)
}

func TestLeaseAcquireContendedReturnsNil(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	// A peer holds a lease that has not lapsed.
	writeLeaseDoc(t, s3, leaseObjectKey(testCfg, "genesis"), time.Now().Add(time.Minute))

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.NoError(t, err, "contention is not an error")
	require.Nil(t, lease)
}

func TestLeaseStealsOnlyAfterExpiry(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	key := leaseObjectKey(testCfg, "genesis")

	t.Run("unexpired is not stealable", func(t *testing.T) {
		s3 := newFakeS3()
		writeLeaseDoc(t, s3, key, time.Now().Add(time.Second))

		lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
		require.NoError(t, err)
		require.Nil(t, lease)
	})

	t.Run("expired is stealable", func(t *testing.T) {
		s3 := newFakeS3()
		writeLeaseDoc(t, s3, key, time.Now().Add(-time.Second))

		lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
		require.NoError(t, err)
		require.NotNil(t, lease)
		require.NoError(t, lease.Release(ctx))
	})
}

func TestLeaseConcurrentStealAdmitsExactlyOne(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	writeLeaseDoc(t, s3, leaseObjectKey(testCfg, "genesis"), time.Now().Add(-time.Second))

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		winner []*Lease
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
			require.NoError(t, err)
			if lease != nil {
				mu.Lock()
				winner = append(winner, lease)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	require.Len(t, winner, 1, "exactly one racer may steal an expired lease")
	require.NoError(t, winner[0].Release(ctx))
}

func TestLeaseRetriesConditionalConflict(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	// S3 returns 409 when concurrent conditional writes race internally. That is
	// retryable and must not be mistaken for contention.
	s3.putConflicts = 2

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, lease)
	require.NoError(t, lease.Release(ctx))
}

func TestLeaseHeartbeatRenews(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	key := leaseObjectKey(testCfg, "genesis")

	lease, err := TryAcquireLease(
		ctx,
		testCfg,
		s3,
		testLeaseBucket,
		"genesis",
		150*time.Millisecond,
	)
	require.NoError(t, err)
	require.NotNil(t, lease)
	first := s3.currentETag(key)

	require.Eventually(t, func() bool {
		return s3.currentETag(key) != first
	}, 2*time.Second, 10*time.Millisecond, "heartbeat should rewrite the lease")

	require.NoError(t, lease.Context().Err(), "renewing lease stays live")
	require.NoError(t, lease.Release(ctx))
}

// A lease can lapse without being stolen: the ETag still matches, so only the
// document's expiry reveals it.
func TestLeaseVerifyRejectsLapsedLease(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	key := leaseObjectKey(testCfg, "genesis")

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, lease)
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
	require.NoError(t, lease.Verify(ctx))

	writeLeaseDoc(t, s3, key, time.Now().Add(-time.Minute))
	lease.setGuard(s3.currentETag(key))

	err = lease.Verify(ctx)

	require.ErrorIs(t, err, ErrLeaseLost)
	require.ErrorContains(t, err, "lapsed before renewal")
}

func TestLeaseHeartbeatDetectsTheft(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	key := leaseObjectKey(testCfg, "genesis")

	lease, err := TryAcquireLease(
		ctx,
		testCfg,
		s3,
		testLeaseBucket,
		"genesis",
		150*time.Millisecond,
	)
	require.NoError(t, err)
	require.NotNil(t, lease)

	// A peer steals it: the object's ETag moves, so our next heartbeat 412s.
	writeLeaseDoc(t, s3, key, time.Now().Add(time.Minute))

	select {
	case <-lease.Context().Done():
		require.ErrorIs(t, context.Cause(lease.Context()), ErrLeaseLost)
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not detect the stolen lease")
	}

	// Release must not delete the thief's object.
	stolen := s3.currentETag(key)
	require.NoError(t, lease.Release(ctx))
	require.Equal(t, stolen, s3.currentETag(key), "release is conditional on our ETag")
}

// S3 answers a conditional write against a missing object with 404, not 412, so
// a deleted lease object must read as lost ownership rather than a retryable
// blip that keeps the lease live until expiry.
func TestLeaseHeartbeatDetectsDeletedObject(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	key := leaseObjectKey(testCfg, "genesis")

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Second)
	require.NoError(t, err)
	require.NotNil(t, lease)

	s3.mu.Lock()
	delete(s3.objects, key)
	s3.mu.Unlock()

	select {
	case <-lease.Context().Done():
		require.ErrorIs(t, context.Cause(lease.Context()), ErrLeaseLost)
		require.ErrorContains(t, context.Cause(lease.Context()), "lease object is gone")
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not detect the deleted lease")
	}
}

// The holder releasing between our read and our steal is the create-only case
// again, not a failure: the next attempt simply wins the empty key.
func TestLeaseClaimRetriesWhenHolderReleasesMidSteal(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	key := leaseObjectKey(testCfg, "genesis")

	// A lapsed holder, so the claim reaches its steal path.
	writeLeaseDoc(t, s3, key, time.Now().Add(-time.Minute))
	puts := 0
	s3.beforePut = func(k string) {
		puts++
		if puts == 2 {
			delete(s3.objects, k) // released between our get and our steal
		}
	}

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)

	require.NoError(t, err, "a clean release mid-steal must not fail the claim")
	require.NotNil(t, lease)
	t.Cleanup(func() { _ = lease.Release(context.Background()) })
}

func TestAcquireLeaseBlocksUntilContextEnds(t *testing.T) {
	setLeaseTestEnv(t)
	s3 := newFakeS3()
	writeLeaseDoc(t, s3, leaseObjectKey(testCfg, "genesis"), time.Now().Add(time.Hour))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	lease, err := AcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.Nil(t, lease)
	require.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestAcquireLeaseReturnsImmediatelyWhenFree(t *testing.T) {
	setLeaseTestEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s3 := newFakeS3()

	lease, err := AcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, lease)
	require.NoError(t, lease.Release(ctx))
}

func TestLeaseUnparseableObjectIsStealable(t *testing.T) {
	setLeaseTestEnv(t)
	ctx := context.Background()
	s3 := newFakeS3()
	// A corrupt lease must not wedge the lock forever.
	s3.putRawObject(leaseObjectKey(testCfg, "genesis"), []byte("not json"))

	lease, err := TryAcquireLease(ctx, testCfg, s3, testLeaseBucket, "genesis", time.Minute)
	require.NoError(t, err)
	require.NotNil(t, lease)
	require.NoError(t, lease.Release(ctx))
}
