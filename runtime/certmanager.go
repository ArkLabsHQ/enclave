package runtime

// Shared-certificate lifecycle: one certificate for the whole fleet, renewed by
// exactly one enclave at a time under the S3 lease.
//
// Issuance is deliberately not lazy. With a shared certificate, renewing inside
// the TLS handshake would be a thundering herd, and the first client after expiry
// would wait out a multi-minute DNS-01 order.

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync/atomic"
	"time"
)

const (
	certLeaseName = "acme-renewal"

	// renewBefore starts renewal well inside Let's Encrypt's 90-day lifetime.
	renewBefore = 30 * 24 * time.Hour

	// certHardFloor is the point at which a still-stale certificate stops being
	// a warning and starts being an outage in waiting.
	certHardFloor = 7 * 24 * time.Hour

	certPollMin = 5 * time.Minute
	certPollMax = 15 * time.Minute

	// certIssueTimeout bounds one DNS-01 order.
	certIssueTimeout = 10 * time.Minute
)

// certIssuer produces a certificate for a domain. An interface so tests can
// exercise the commit ordering without an ACME server.
type certIssuer interface {
	issue(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error)
}

// certManager serves the shared certificate and keeps it fresh.
type certManager struct {
	store  *certStore
	issuer certIssuer
	s3     S3API
	bucket string
	fqdn   string
	hashes AttestationHashes

	// current is swapped wholesale so the served certificate, the attested
	// fingerprint and the stored version it came from can never disagree.
	current atomic.Pointer[certBundle]
}

func newCertManager(
	store *certStore,
	issuer certIssuer,
	s3api S3API,
	bucket, fqdn string,
	hashes AttestationHashes,
) *certManager {
	return &certManager{
		store:  store,
		issuer: issuer,
		s3:     s3api,
		bucket: bucket,
		fqdn:   fqdn,
		hashes: hashes,
	}
}

// GetCertificate serves the installed bundle. It never issues.
func (m *certManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	bundle := m.current.Load()
	if bundle == nil {
		return nil, errors.New("no certificate available yet")
	}
	return bundle.cert, nil
}

// storeBundle installs a certificate: served bundle, attested fingerprint and
// the stored version it came from, all in one step.
//
// These must move as one. A window where the enclave serves leaf B while
// attesting leaf A fails *every* pinning client, because the whole point of
// tlsKeyHash is that the two agree.
func (m *certManager) storeBundle(bundle *certBundle) {
	m.hashes.SetTLSKeyHash(bundle.leafHash)
	m.current.Store(bundle)
	slog.Info("installed TLS certificate",
		"sha256", hex.EncodeToString(bundle.leafHash[:]),
		"not_after", bundle.notAfter.UTC().Format(time.RFC3339))
}

// bootstrap loads the shared certificate, issuing one if the fleet has none.
// It blocks: the listener must not start without a certificate.
func (m *certManager) bootstrap(ctx context.Context) error {
	bundle, err := m.store.loadCert(ctx)
	if err != nil {
		return err
	}
	if bundle != nil {
		m.storeBundle(bundle)
		return nil
	}

	// Reads do not need the lease; it guards issuance. The unlocked check above
	// keeps every boot but the fleet's first off the lock, and the re-check below
	// — under the lease — is what stops two enclaves that both saw "no
	// certificate" from both ordering one.
	slog.Info("no shared certificate found, issuing", "fqdn", m.fqdn)
	lease, err := AcquireLease(ctx, m.s3, m.bucket, certLeaseName, leaseTTL)
	if err != nil {
		return fmt.Errorf("acquire renewal lease for first issuance: %w", err)
	}
	defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()

	// A peer may have issued while we queued.
	if bundle, err = m.store.loadCert(ctx); err != nil {
		return err
	}
	if bundle != nil {
		m.storeBundle(bundle)
		return nil
	}
	// Still nothing stored, so the write must be create-only.
	return m.renew(ctx, "")
}

// Run polls for a peer's renewal and renews when the certificate ages out.
func (m *certManager) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitteredPoll()):
		}
		if err := m.tick(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("certificate refresh failed", "error", err)
		}
	}
}

func (m *certManager) tick(ctx context.Context) error {
	// Cheap poll: an ETag change means a peer renewed, so adopt theirs.
	etag, err := m.store.certETag(ctx)
	if err != nil {
		return err
	}
	if etag != "" && etag != m.currentETag() {
		bundle, err := m.store.loadCert(ctx)
		if err != nil {
			return err
		}
		if bundle != nil {
			m.storeBundle(bundle)
		}
	}

	bundle := m.current.Load()
	if bundle == nil {
		return m.renewUnderLease(ctx, "")
	}
	if time.Until(bundle.notAfter) > renewBefore {
		return nil
	}
	// bundle.etag is the version backing the certificate we serve right now —
	// exactly the snapshot the conditional write needs.
	if err := m.renewUnderLease(ctx, bundle.etag); err != nil {
		return err
	}
	// Post-renewal: renewUnderLease is silent whether it renewed or deferred to a
	// peer, so only the certificate we now serve says if we are in trouble.
	if left := time.Until(m.current.Load().notAfter); left < certHardFloor {
		slog.Error("shared certificate is close to expiry and not renewing",
			"fqdn", m.fqdn, "expires_in", left.Truncate(time.Minute).String())
	}
	return nil
}

// renewUnderLease renews only if this enclave wins the lease; otherwise the peer
// holding it is already doing the work and the next poll picks up the result.
func (m *certManager) renewUnderLease(ctx context.Context, certETag string) error {
	lease, err := TryAcquireLease(ctx, m.s3, m.bucket, certLeaseName, leaseTTL)
	if err != nil {
		return fmt.Errorf("acquire renewal lease: %w", err)
	}
	if lease == nil {
		return nil // a peer is renewing
	}
	defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()

	return m.renew(ctx, certETag)
}

// renew issues a new certificate and commits it against certETag.
//
// certETag is captured by the caller *before* the order begins and must not be
// refreshed here. It is a snapshot of what the world looked like when the order
// started, which is what makes the conditional write mean "nothing happened while
// I was gone". Re-reading it immediately before the write would let a zombie
// issuer — one whose lease lapsed while it was descheduled — overwrite the peer
// that took over, and the code would still look correct.
func (m *certManager) renew(ctx context.Context, certETag string) error {
	ctx, cancel := context.WithTimeout(ctx, certIssueTimeout)
	defer cancel()

	certPEM, keyPEM, err := m.issuer.issue(ctx, m.fqdn)
	if err != nil {
		return fmt.Errorf("issue certificate for %q: %w", m.fqdn, err)
	}

	// S3 first, memory second: installing a certificate whose write was rejected
	// would leave this enclave serving a leaf no peer has, with its attestation
	// bound to it, breaking any client that took attestation from a peer.
	bundle, err := m.store.saveCert(ctx, certPEM, keyPEM, certETag)
	if err != nil {
		if errors.Is(err, errCertChanged) {
			slog.Info("peer renewed the certificate first, adopting theirs")
			return m.adoptPeerCert(ctx)
		}
		return err
	}

	m.storeBundle(bundle)
	return nil
}

func (m *certManager) adoptPeerCert(ctx context.Context) error {
	bundle, err := m.store.loadCert(ctx)
	if err != nil {
		return err
	}
	if bundle == nil {
		return errors.New("certificate vanished after a conflicting write")
	}
	m.storeBundle(bundle)
	return nil
}

func (m *certManager) currentETag() string {
	if bundle := m.current.Load(); bundle != nil {
		return bundle.etag
	}
	return ""
}

func jitteredPoll() time.Duration {
	spread := certPollMax - certPollMin
	return certPollMin + time.Duration(rand.Int63n(int64(spread)+1))
}
