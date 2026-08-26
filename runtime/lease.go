package runtime

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
	// leaseTTL bounds how long a dead holder can block its peers.
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

// Lease is a held S3 lease kept alive by a background heartbeat.
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

	mu sync.Mutex

	guard     string
	expiresAt time.Time
}

func TryAcquireLease(
	ctx context.Context,
	s3api S3API,
	bucket, name string,
	ttl time.Duration,
) (*Lease, error) {
	l := &Lease{s3: s3api, bucket: bucket, key: leaseObjectKey(name), ttl: ttl}
	won, err := l.claim(ctx)
	if err != nil || !won {
		return nil, err
	}
	l.start()
	return l, nil
}

// AcquireLease blocks until the lease is held or ctx ends.
func AcquireLease(
	ctx context.Context,
	s3api S3API,
	bucket, name string,
	ttl time.Duration,
) (*Lease, error) {
	for {
		lease, err := TryAcquireLease(ctx, s3api, bucket, name, ttl)
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

func (l *Lease) Verify(ctx context.Context) error {
	if l.ctx.Err() != nil {
		return fmt.Errorf("%w: %s: %w", ErrLeaseLost, l.key, context.Cause(l.ctx))
	}
	_, live, err := l.get(ctx)
	if err != nil {
		if isNoSuchKey(err) {
			return fmt.Errorf("%w: %s: lease object is gone", ErrLeaseLost, l.key)
		}
		return fmt.Errorf("verify lease %q: %w", l.key, err)
	}
	if live != l.currentGuard() {
		return fmt.Errorf("%w: %s: taken over by a peer", ErrLeaseLost, l.key)
	}
	return nil
}

// Release relinquishes the lease.
func (l *Lease) Release(ctx context.Context) error {
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done // hands guard ownership over from the heartbeat goroutine
	l.cancel(errLeaseReleased)

	guard := l.currentGuard()
	if guard == "" {
		return nil
	}
	_, err := l.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket:  aws.String(l.bucket),
		Key:     aws.String(l.key),
		IfMatch: aws.String(guard),
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

// start begins the heartbeat that keeps the lease alive and detects its loss.
func (l *Lease) start() {
	l.ctx, l.cancel = context.WithCancelCause(context.Background())
	l.stop = make(chan struct{})
	l.done = make(chan struct{})
	go l.heartbeat()
}

// heartbeat renews the lease every ttl/3 and is the loss detector
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
		guard, expiresAt, err := l.put(ctx)
		cancel()

		switch {
		case err == nil:
			l.renewedAt(guard, expiresAt)
		case isPreconditionFailed(err):
			l.cancel(fmt.Errorf("%w: %s", ErrLeaseLost, l.key))
			return
		case l.lapsed():
			l.cancel(
				fmt.Errorf("%w: %s: heartbeat failed past expiry: %w", ErrLeaseLost, l.key, err),
			)
			return
		default:
			slog.Warn("lease heartbeat failed, retrying", "key", l.key, "error", err)
		}
	}
}

// claim wins the lease and records its guard, or reports false when a live peer
// holds it. Runs before the heartbeat starts, so it writes the fields directly.
func (l *Lease) claim(ctx context.Context) (bool, error) {
	for attempt := 0; attempt <= leaseConflictRetries; attempt++ {
		l.setEmptyGuard()
		guard, expiresAt, err := l.put(ctx)
		switch {
		case err == nil:
			l.guard, l.expiresAt = guard, expiresAt
			return true, nil
		case isConditionalConflict(err):
			if err := backoff(ctx, attempt); err != nil {
				return false, err
			}
			continue
		case !isPreconditionFailed(err):
			return false, fmt.Errorf("lease claim %q: %w", l.key, err)
		}

		// Held by an enclave. Steal only once their lease has lapsed.
		doc, theirs, err := l.get(ctx)
		if isNoSuchKey(err) {
			continue // released between our put and our get
		}
		if err != nil {
			return false, err
		}
		if !doc.lapsed(time.Now()) {
			return false, nil
		}

		l.setGuard(theirs)
		guard, expiresAt, err = l.put(ctx)
		switch {
		case err == nil:
			l.guard, l.expiresAt = guard, expiresAt
			return true, nil
		case isPreconditionFailed(err):
			return false, nil // a peer stole it first
		case isConditionalConflict(err):
			if err := backoff(ctx, attempt); err != nil {
				return false, err
			}
			continue
		default:
			return false, fmt.Errorf("lease steal %q: %w", l.key, err)
		}
	}
	return false, fmt.Errorf("lease claim %q: too many conditional conflicts", l.key)
}

// insertCondition applies the lease's expectation to a put, so S3, not this
// process, decides whether the write is allowed.
func (l *Lease) insertCondition(in *s3.PutObjectInput) {
	if guard := l.currentGuard(); guard != "" {
		in.IfMatch = aws.String(guard)
		return
	}
	in.IfNoneMatch = aws.String("*")
}

// setEmptyGuard makes the next put create-only.
func (l *Lease) setEmptyGuard() { l.setGuard("") }

// setGuard records the version the next put must find.
func (l *Lease) setGuard(guard string) {
	l.mu.Lock()
	l.guard = guard
	l.mu.Unlock()
}

func (l *Lease) currentGuard() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.guard
}

func (l *Lease) renewedAt(guard string, expiresAt time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.guard, l.expiresAt = guard, expiresAt
}

func (l *Lease) lapsed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Now().After(l.expiresAt)
}

func (l *Lease) put(ctx context.Context) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(l.ttl)
	body, err := json.Marshal(leaseDocV1{
		AcquiredAt: now.Unix(),
		ExpiresAt:  expiresAt.Unix(),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode lease: %w", err)
	}

	in := &s3.PutObjectInput{
		Bucket:      aws.String(l.bucket),
		Key:         aws.String(l.key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	}

	l.insertCondition(in)

	out, err := l.s3.PutObject(ctx, in)
	if err != nil {
		return "", time.Time{}, err
	}
	etag := aws.ToString(out.ETag)
	if etag == "" {
		return "", time.Time{}, fmt.Errorf("lease put %q: S3 returned no ETag", l.key)
	}
	return etag, expiresAt, nil
}

func (l *Lease) get(ctx context.Context) (leaseDocV1, string, error) {
	out, err := l.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(l.key),
	})
	if err != nil {
		return leaseDocV1{}, "", err
	}
	defer func() { _ = out.Body.Close() }()

	raw, err := io.ReadAll(out.Body)
	if err != nil {
		return leaseDocV1{}, "", fmt.Errorf("read lease %q: %w", l.key, err)
	}
	var doc leaseDocV1
	if err := json.Unmarshal(raw, &doc); err != nil {
		slog.Warn("lease object is unparseable, treating as lapsed", "key", l.key, "error", err)
		return leaseDocV1{}, aws.ToString(out.ETag), nil
	}
	return doc, aws.ToString(out.ETag), nil
}

// lapsed reports whether the lease is stealable.
func (d leaseDocV1) lapsed(now time.Time) bool {
	return now.After(time.Unix(d.ExpiresAt, 0))
}

// leaseObjectKey namespaces locks inside the storage bucket.
func leaseObjectKey(name string) string {
	return fmt.Sprintf("%s/%s/lock/%s", getDeployment(), getAppName(), name)
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
