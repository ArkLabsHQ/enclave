package runtime

// Shared-certificate lifecycle: one certificate for the whole fleet, renewed by
// exactly one enclave at a time under the S3 lease.
//
// Issuance is deliberately not lazy. With a shared certificate, renewing inside
// the TLS handshake would be a thundering herd, and the first client after expiry
// would wait out a multi-minute DNS-01 order.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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

type certIssuer interface {
	Issue(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error)
}

// certManager serves the shared certificate and keeps it fresh.
type certManager struct {
	store       *certStore
	issuer      certIssuer
	s3          S3API
	leaseBucket string
	fqdn        string
	hashes      *AttestationHashes

	currentCert atomic.Pointer[certBundle]
}

func newCertManager(
	ctx context.Context,
	store *certStore,
	issuer certIssuer,
	s3api S3API,
	leaseBucket, fqdn string,
	hashes *AttestationHashes,
) (*certManager, error) {
	m := &certManager{
		store:       store,
		issuer:      issuer,
		s3:          s3api,
		leaseBucket: leaseBucket,
		fqdn:        fqdn,
		hashes:      hashes,
	}

	bundle, err := m.resolve(ctx)
	if err != nil {
		return nil, err
	}
	m.currentCert.Store(bundle)

	hashes.SetTLSKeyHashSource(func() ([sha256.Size]byte, bool) {
		return m.currentCert.Load().leafHash, true
	})
	return m, nil
}

func (m *certManager) resolve(ctx context.Context) (*certBundle, error) {
	bundle, err := m.store.LoadCert(ctx)
	if err != nil {
		return nil, err
	}
	if bundle != nil {
		return bundle, nil
	}

	// Prevents duplicate issuance if multiple enclaves start up at once.
	slog.Info("no shared certificate found, issuing", "fqdn", m.fqdn)
	lease, err := AcquireLease(ctx, m.s3, m.leaseBucket, certLeaseName, leaseTTL)
	if err != nil {
		return nil, fmt.Errorf("acquire renewal lease for first issuance: %w", err)
	}
	defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()

	// A peer may have issued while we queued.
	if bundle, err = m.store.LoadCert(ctx); err != nil {
		return nil, err
	}
	if bundle != nil {
		return bundle, nil
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

func (m *certManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.currentCert.Load().cert, nil
}

// tick adopts a peer's renewal when the stored ETag moves, and renews when the certificate is inside renewBefore.
func (m *certManager) tick(ctx context.Context) error {
	// A changed ETag means a peer renewed, so adopt theirs.
	stored, err := m.store.LoadCert(ctx)
	if err != nil {
		return err
	}
	if stored != nil && stored.etag != m.currentETag() {
		m.currentCert.Store(stored)
	}

	bundle := m.currentCert.Load()
	if time.Until(bundle.notAfter) > renewBefore {
		return nil
	}

	renewed, err := m.renewUnderLease(ctx, bundle.etag)
	if err != nil {
		return err
	}
	if renewed != nil {
		m.currentCert.Store(renewed)
	}

	if left := time.Until(m.currentCert.Load().notAfter); left < certHardFloor {
		slog.Error("shared certificate is close to expiry and not renewing",
			"fqdn", m.fqdn, "expires_in", left.Truncate(time.Minute).String())
	}
	return nil
}

// renewUnderLease renews only if this enclave wins the lease;
func (m *certManager) renewUnderLease(ctx context.Context, certETag string) (*certBundle, error) {
	lease, err := TryAcquireLease(ctx, m.s3, m.leaseBucket, certLeaseName, leaseTTL)
	if err != nil {
		return nil, fmt.Errorf("acquire renewal lease: %w", err)
	}
	if lease == nil {
		return nil, nil // a peer is renewing
	}
	defer func() { _ = lease.Release(context.WithoutCancel(ctx)) }()

	return m.renew(ctx, certETag)
}

// renew issues a new certificate and commits it against certETag.
func (m *certManager) renew(ctx context.Context, certETag string) (*certBundle, error) {
	ctx, cancel := context.WithTimeout(ctx, certIssueTimeout)
	defer cancel()

	certPEM, keyPEM, err := m.issuer.Issue(ctx, m.fqdn)
	if err != nil {
		return nil, fmt.Errorf("issue certificate for %q: %w", m.fqdn, err)
	}

	bundle, err := m.store.SaveCert(ctx, certPEM, keyPEM, certETag)
	if err != nil {
		if errors.Is(err, errCertChanged) {
			slog.Info("peer renewed the certificate first, adopting theirs")
			bundle, err := m.store.LoadCert(ctx)
			if err != nil {
				return nil, err
			}
			if bundle == nil {
				return nil, errors.New("certificate vanished after a conflicting write")
			}
			return bundle, nil
		}
		return nil, err
	}
	return bundle, nil
}

func (m *certManager) currentETag() string {
	return m.currentCert.Load().etag
}

func jitteredPoll() time.Duration {
	spread := certPollMax - certPollMin
	return certPollMin + time.Duration(rand.Int63n(int64(spread)+1))
}
