package runtime

// S3 conditional-write lease. Every transition is guarded by an S3 conditional
// write, so the ETag returned by the last successful write *is* the claim: the
// object body carries only an expiry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

const (
	// leaseTTL bounds how long a dead holder blocks its peers. Renewing at
	// ttl/3 leaves a live holder at least 2*ttl/3 of remaining lease at all
	// times, which is the margin that absorbs clock skew between enclaves: a
	// peer would need minutes of skew to rob a healthy holder, so expiry needs
	// no extra padding.
	leaseTTL = 5 * time.Minute

	// leaseConflictRetries bounds retries of S3's retryable 409.
	leaseConflictRetries = 5

	leaseConflictBackoff = 50 * time.Millisecond

	// leasePollInterval is how often a blocking acquire re-checks a held lease.
	leasePollInterval = 5 * time.Second

	// leaseWriteTimeout bounds a single heartbeat write.
	leaseWriteTimeout = 10 * time.Second
)

var (
	// ErrLeaseLost reports that a peer stole the lease out from under us.
	ErrLeaseLost = errors.New("lease: lost")

	errLeaseReleased = errors.New("lease: released")
)

// leaseDocV1 is the lease object body. Only expires_at is ever read.
type leaseDocV1 struct {
	AcquiredAt int64 `json:"acquired_at"`
	ExpiresAt  int64 `json:"expires_at"`
}

// lapsed reports whether the lease is stealable.
func (d leaseDocV1) lapsed(now time.Time) bool {
	return now.After(time.Unix(d.ExpiresAt, 0))
}

// Lease is a held S3 lease, kept alive by a single background goroutine that
// solely owns the object and the ETag. Callers scope their work to Context() so
// a stolen lease cancels it; they never write to the lease themselves.
type Lease struct {
	s3     S3API
	bucket string
	key    string
	ttl    time.Duration

	ctx    context.Context
	cancel context.CancelCauseFunc

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}

	// etag and expiresAt belong to the heartbeat goroutine until done is
	// closed; closing it hands ownership to Release.
	etag      string
	expiresAt time.Time
}

// leaseObjectKey namespaces locks inside the storage bucket.
func leaseObjectKey(name string) string {
	return fmt.Sprintf("%s/%s/lock/%s", getDeployment(), getAppName(), name)
}

// AcquireLease blocks until the lease is held or ctx ends.
func AcquireLease(
	ctx context.Context,
	s3api S3API,
	bucket, name string,
	ttl time.Duration,
) (*Lease, error) {
	for {
		lease, err := tryAcquireLease(ctx, s3api, bucket, name, ttl)
		if err != nil {
			return nil, err
		}
		if lease != nil {
			return lease, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("acquire lease %q: %w", name, ctx.Err())
		case <-time.After(leasePollInterval):
		}
	}
}

func (l *Lease) Context() context.Context { return l.ctx }

// Release stops the heartbeat and drops the object. Conditional on our ETag, so
// a lease already stolen is left alone.
func (l *Lease) Release(ctx context.Context) error {
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done // hands etag ownership over from the heartbeat goroutine
	l.cancel(errLeaseReleased)

	if l.etag == "" {
		return nil
	}
	_, err := l.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:  aws.String(l.bucket),
		Key:     aws.String(l.key),
		IfMatch: aws.String(l.etag),
	})
	switch {
	case err == nil:
		return nil
	case isPreconditionFailed(err), isNoSuchKey(err):
		slog.Warn("lease was no longer ours at release", "key", l.key)
		return nil
	default:
		return fmt.Errorf("lease release %q: %w", l.key, err)
	}
}

// leaseOption configures acquisition.
type leaseOption func(*leaseConfig)

type leaseConfig struct{ steal bool }

// withoutSteal refuses to take over a lapsed lease, so a holder that dies
// mid-operation wedges the lock until an operator clears it. Use it when
// resuming someone else's half-finished work is more dangerous than failing:
// the operation must then be idempotent-or-nothing, not idempotent-or-retry.
func withoutSteal() leaseOption {
	return func(c *leaseConfig) { c.steal = false }
}

func tryAcquireLease(
	ctx context.Context,
	s3api S3API,
	bucket, name string,
	ttl time.Duration,
	opts ...leaseOption,
) (*Lease, error) {
	cfg := leaseConfig{steal: true}
	for _, opt := range opts {
		opt(&cfg)
	}

	key := leaseObjectKey(name)
	etag, expiresAt, err := claimLease(ctx, s3api, bucket, key, ttl, cfg)
	if err != nil || etag == "" {
		return nil, err
	}
	return startLease(s3api, bucket, key, ttl, etag, expiresAt), nil
}

func startLease(
	s3api S3API,
	bucket, key string,
	ttl time.Duration,
	etag string,
	expiresAt time.Time,
) *Lease {
	ctx, cancel := context.WithCancelCause(context.Background())
	l := &Lease{
		s3:        s3api,
		bucket:    bucket,
		key:       key,
		ttl:       ttl,
		ctx:       ctx,
		cancel:    cancel,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		etag:      etag,
		expiresAt: expiresAt,
	}
	go l.heartbeat()
	return l
}

// heartbeat renews the lease every ttl/3 and is the loss detector: a 412 means a
// peer stole it, which cancels the lease context so leased work unwinds.
func (l *Lease) heartbeat() {
	defer close(l.done)

	ticker := time.NewTicker(l.ttl / 3)
	defer ticker.Stop()

	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
		}

		ctx, cancel := context.WithTimeout(context.Background(), leaseWriteTimeout)
		etag, expiresAt, err := putLease(ctx, l.s3, l.bucket, l.key, l.ttl, ifMatch(l.etag))
		cancel()

		switch {
		case err == nil:
			l.etag, l.expiresAt = etag, expiresAt
		case isPreconditionFailed(err):
			l.cancel(fmt.Errorf("%w: %s", ErrLeaseLost, l.key))
			return
		case time.Now().After(l.expiresAt):
			l.cancel(fmt.Errorf("%w: %s: heartbeat failed past expiry: %w", ErrLeaseLost, l.key, err))
			return
		default:
			slog.Warn("lease heartbeat failed, retrying", "key", l.key, "error", err)
		}
	}
}

// claimLease returns the ETag of a won lease, or "" when another enclave holds
// it (or holds it unrecoverably, under withoutSteal).
func claimLease(
	ctx context.Context,
	s3api S3API,
	bucket, key string,
	ttl time.Duration,
	cfg leaseConfig,
) (string, time.Time, error) {
	for attempt := 0; attempt <= leaseConflictRetries; attempt++ {
		// Uncontended: succeeds only if the object is absent.
		etag, expiresAt, err := putLease(ctx, s3api, bucket, key, ttl, ifNoneMatchAny())
		switch {
		case err == nil:
			return etag, expiresAt, nil
		case isConditionalConflict(err):
			if err := backoff(ctx, attempt); err != nil {
				return "", time.Time{}, err
			}
			continue
		case !isPreconditionFailed(err):
			return "", time.Time{}, fmt.Errorf("lease claim %q: %w", key, err)
		}

		if !cfg.steal {
			return "", time.Time{}, nil
		}

		// Held by an enclave. Steal only once their lease has lapsed.
		doc, curETag, err := getLease(ctx, s3api, bucket, key)
		if isNoSuchKey(err) {
			continue // released between our put and our get
		}
		if err != nil {
			return "", time.Time{}, err
		}
		if !doc.lapsed(time.Now()) {
			return "", time.Time{}, nil
		}

		etag, expiresAt, err = putLease(ctx, s3api, bucket, key, ttl, ifMatch(curETag))
		switch {
		case err == nil:
			return etag, expiresAt, nil
		case isPreconditionFailed(err):
			return "", time.Time{}, nil // a peer stole it first
		case isConditionalConflict(err):
			if err := backoff(ctx, attempt); err != nil {
				return "", time.Time{}, err
			}
			continue
		default:
			return "", time.Time{}, fmt.Errorf("lease steal %q: %w", key, err)
		}
	}
	return "", time.Time{}, fmt.Errorf("lease claim %q: too many conditional conflicts", key)
}

type leaseCondition func(*s3.PutObjectInput)

func ifMatch(etag string) leaseCondition {
	return func(in *s3.PutObjectInput) { in.IfMatch = aws.String(etag) }
}

func ifNoneMatchAny() leaseCondition {
	return func(in *s3.PutObjectInput) { in.IfNoneMatch = aws.String("*") }
}

func putLease(
	ctx context.Context,
	s3api S3API,
	bucket, key string,
	ttl time.Duration,
	cond leaseCondition,
) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(ttl)
	body, err := json.Marshal(leaseDocV1{
		AcquiredAt: now.Unix(),
		ExpiresAt:  expiresAt.Unix(),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode lease: %w", err)
	}

	in := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	}

	cond(in)

	out, err := s3api.PutObject(ctx, in)
	if err != nil {
		return "", time.Time{}, err
	}
	etag := aws.ToString(out.ETag)
	if etag == "" {
		return "", time.Time{}, fmt.Errorf("lease put %q: S3 returned no ETag", key)
	}
	return etag, expiresAt, nil
}

func getLease(
	ctx context.Context,
	s3api S3API,
	bucket, key string,
) (leaseDocV1, string, error) {
	out, err := s3api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return leaseDocV1{}, "", err
	}
	defer func() { _ = out.Body.Close() }()

	raw, err := io.ReadAll(out.Body)
	if err != nil {
		return leaseDocV1{}, "", fmt.Errorf("read lease %q: %w", key, err)
	}
	var doc leaseDocV1
	if err := json.Unmarshal(raw, &doc); err != nil {
		slog.Warn("lease object is unparseable, treating as lapsed", "key", key, "error", err)
		return leaseDocV1{}, aws.ToString(out.ETag), nil
	}
	return doc, aws.ToString(out.ETag), nil
}

func backoff(ctx context.Context, attempt int) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(leaseConflictBackoff << attempt):
		return nil
	}
}

// s3ErrorCode returns the S3 API error code, or "" for non-API errors.
func s3ErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// isPreconditionFailed reports S3's 412: the condition genuinely did not hold,
// i.e. someone else holds the lease.
func isPreconditionFailed(err error) bool {
	return s3ErrorCode(err) == "PreconditionFailed"
}

// isConditionalConflict reports S3's 409: concurrent conditional writes raced
// inside S3. This is retryable and must NOT be read as contention.
func isConditionalConflict(err error) bool {
	return s3ErrorCode(err) == "ConditionalRequestConflict"
}

func isNoSuchKey(err error) bool {
	switch s3ErrorCode(err) {
	case "NoSuchKey", "NotFound":
		return true
	}
	return false
}
