package runtime

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const certTestBucket = "cert-bucket"

func setCertTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "app")
}

// issueTestCertWithKey mints a self-signed leaf standing in for a CA-issued one.
func issueTestCertWithKey(
	t *testing.T,
	cn string,
	notAfter time.Time,
	key crypto.Signer,
) []byte {
	t.Helper()
	return issueTestCertWithKeyAt(t, cn, time.Now().Add(-time.Hour), notAfter, key)
}

func issueTestCertWithKeyAt(
	t *testing.T,
	cn string,
	notBefore, notAfter time.Time,
	key crypto.Signer,
) []byte {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// fakeIssuer hands out a fresh certificate per call and counts orders, standing
// in for a CA so rate-limit-sensitive ordering can be asserted.
type fakeIssuer struct {
	t        *testing.T
	cn       string
	notAfter time.Time
	calls    int
	err      error
	// onIssue runs mid-order, letting a test simulate a peer acting while this
	// enclave is descheduled.
	onIssue func()
}

func (f *fakeIssuer) Issue(ctx context.Context, _ string, key crypto.Signer) ([]byte, error) {
	// A real CA order dies with its context; a fake that ignores it cannot show
	// that losing the lease stops the work.
	if ctx.Err() != nil {
		return nil, context.Cause(ctx)
	}
	f.calls++
	if f.onIssue != nil {
		f.onIssue()
	}
	if f.err != nil {
		return nil, f.err
	}
	notAfter := f.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	return issueTestCertWithKey(f.t, f.cn, notAfter, key), nil
}

// attestedHash is the user_data payload for a leaf: the prefix plus its SHA-256.
func attestedHash(leaf [sha256.Size]byte) []byte {
	return append([]byte(hashPrefix), leaf[:]...)
}

func certKeyHash(t *testing.T, certDER []byte) [sha256.Size]byte {
	t.Helper()
	leaf, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
}

func TestSelfSignedIssuerSharesOneCertAcrossTheFleet(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	key := newTestTLSKey(t)
	firstStore := newCertStore(
		s3f,
		&dek{key: make([]byte, 32)},
		key,
		certTestBucket,
		"enclave.test",
	)
	secondStore := newCertStore(
		s3f,
		&dek{key: make([]byte, 32)},
		key,
		certTestBucket,
		"enclave.test",
	)

	first, firstHashes := newCertTestManagerForStore(t, firstStore, selfSignedIssuer{})
	second, secondHashes := newCertTestManagerForStore(t, secondStore, selfSignedIssuer{})

	firstCert, err := first.GetCertificate(nil)
	require.NoError(t, err)
	secondCert, err := second.GetCertificate(nil)
	require.NoError(t, err)

	require.Equal(t, firstCert.Certificate[0], secondCert.Certificate[0],
		"every enclave must serve the leaf a client could have pinned from any other")
	require.Equal(t, firstHashes.Serialize(), secondHashes.Serialize(),
		"and must publish that leaf as the hash clients pin against")
}

func TestSaveCertRejectsAnUnusableLeaf(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		cn      string
		expires time.Time
		notYet  bool
		wantErr string
	}{
		{
			name:    "expired",
			cn:      "enclave.test",
			expires: time.Now().Add(-time.Minute),
			wantErr: "expired at",
		},
		{
			name:    "not yet valid",
			cn:      "enclave.test",
			expires: time.Now().Add(24 * time.Hour),
			notYet:  true,
			wantErr: "not valid until",
		},
		{
			name:    "another deployment's name",
			cn:      "someone.else",
			expires: time.Now().Add(24 * time.Hour),
			wantErr: `does not serve "enclave.test"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s3f := newFakeS3()
			store := newCertTestStore(s3f)
			certPEM := issueTestCertWithKey(t, tc.cn, tc.expires, store.key)
			if tc.notYet {
				certPEM = issueTestCertWithKeyAt(
					t, tc.cn, time.Now().Add(time.Hour), tc.expires, store.key,
				)
			}

			_, err := store.SaveCert(ctx, certPEM, "")

			require.ErrorContains(t, err, tc.wantErr)
			stored, loadErr := store.LoadCert(ctx)
			require.NoError(t, loadErr)
			require.Nil(t, stored, "a rejected certificate must not reach the store")
		})
	}
}

// An endpoint addressed by IP needs an IP SAN, or the store's own hostname check
// rejects the certificate this enclave just minted for itself.
func TestSelfSignedIssuerServesAnIPEndpoint(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	store := newCertStore(s3f, &dek{key: make([]byte, 32)}, key, certTestBucket, "192.0.2.10")
	certPEM, err := selfSignedIssuer{}.Issue(ctx, "192.0.2.10", key)
	require.NoError(t, err)

	_, err = store.SaveCert(ctx, certPEM, "")

	require.NoError(t, err)
}

// Nothing in a stored bundle records who issued it, so the two paths must not
// share an object key: an ACME manager that found a self-signed certificate
// would adopt it and never order one.
func TestACMEDoesNotAdoptTheSelfSignedCertificate(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	d := &dek{key: make([]byte, 32)}
	key := newTestTLSKey(t)

	// The fleet ran self-signed first.
	selfSignedStore := newSelfSignedCertStore(s3f, d, key, certTestBucket, "enclave.test")
	_, err := newCertManager(ctx, selfSignedStore, selfSignedIssuer{},
		s3f, certTestBucket, "enclave.test", key, &AttestationHashes{})
	require.NoError(t, err)

	// Then ACME was switched on.
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	acmeStore := newCertStore(s3f, d, key, certTestBucket, "enclave.test")
	withACME, err := newCertManager(ctx, acmeStore, issuer,
		s3f, certTestBucket, "enclave.test", key, &AttestationHashes{})
	require.NoError(t, err)

	require.Equal(t, 1, issuer.calls,
		"enabling ACME must order a certificate, not adopt the self-signed one")
	served, err := withACME.GetCertificate(nil)
	require.NoError(t, err)
	stored, err := selfSignedStore.LoadCert(ctx)
	require.NoError(t, err)
	require.NotEqual(t, stored.cert.Certificate[0], served.Certificate[0])
}

func newCertTestStore(s3f *fakeS3) *certStore {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return newCertStore(s3f, &dek{key: make([]byte, 32)}, key, certTestBucket, "enclave.test")
}

func newTestTLSKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func tryNewCertTestManager(
	s3f *fakeS3,
	issuer certIssuer,
) (*certManager, *AttestationHashes, error) {
	hashes := &AttestationHashes{}
	store := newCertTestStore(s3f)
	m, err := newCertManager(
		context.Background(), store, issuer,
		s3f, certTestBucket, "enclave.test", store.key, hashes,
	)
	return m, hashes, err
}

func newCertTestManager(
	t *testing.T,
	s3f *fakeS3,
	issuer certIssuer,
) (*certManager, *AttestationHashes) {
	t.Helper()
	m, hashes, err := tryNewCertTestManager(s3f, issuer)
	require.NoError(t, err)
	return m, hashes
}

func newCertTestManagerForStore(
	t *testing.T,
	store *certStore,
	issuer certIssuer,
) (*certManager, *AttestationHashes) {
	t.Helper()
	hashes := &AttestationHashes{}
	m, err := newCertManager(
		context.Background(), store, issuer,
		store.s3, store.bucket, store.fqdn, store.key, hashes,
	)
	require.NoError(t, err)
	return m, hashes
}

// A peer that finishes renewing between our read and our lease must be adopted,
// not raced: an order we then have to throw away still costs a rate-limit slot.
func TestRenewUnderLeaseAdoptsAPeerRenewalWithoutOrdering(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test", notAfter: time.Now().Add(time.Hour)}
	m, _ := newCertTestManager(t, s3f, issuer)
	require.Equal(t, 1, issuer.calls)

	// A peer renews and releases while we hold a stale view of the store.
	stale := m.currentCert.Load()
	peer := &fakeIssuer{t: t, cn: "enclave.test"}
	peerKey := stale.cert.PrivateKey.(crypto.Signer)
	peerCert, err := peer.Issue(context.Background(), "enclave.test", peerKey)
	require.NoError(t, err)
	_, err = m.store.SaveCert(context.Background(), peerCert, stale.etag)
	require.NoError(t, err)

	renewed, err := m.renewUnderLease(context.Background(), stale.etag)

	require.NoError(t, err)
	require.NotNil(t, renewed)
	require.Equal(t, 1, issuer.calls, "the peer's certificate must be adopted, not re-ordered")
	require.NotEqual(t, stale.etag, renewed.etag)
}

// Losing the lease mid-order must end the work it was protecting.
func TestRenewWithLeaseStopsWhenTheLeaseIsLost(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	// Already inside renewBefore, so the reload under the lease renews.
	issuer := &fakeIssuer{t: t, cn: "enclave.test", notAfter: time.Now().Add(time.Hour)}
	m, _ := newCertTestManager(t, s3f, issuer)
	require.Equal(t, 1, issuer.calls)

	// A short TTL so the heartbeat notices the theft inside the test.
	lease, err := TryAcquireLease(
		context.Background(), s3f, certTestBucket, "renew-test", time.Second,
	)
	require.NoError(t, err)
	require.NotNil(t, lease)

	// A peer steals it, so the heartbeat cancels the lease context.
	writeLeaseDoc(t, s3f, leaseObjectKey("renew-test"), time.Now().Add(time.Hour))
	require.Eventually(t, func() bool {
		return lease.Context().Err() != nil
	}, 2*time.Second, 10*time.Millisecond, "heartbeat should detect the theft")

	_, err = m.renewWithLease(context.Background(), lease, "")

	require.ErrorIs(t, err, ErrLeaseLost)
	require.Equal(t, 1, issuer.calls, "no order may start once the lease is gone")
}

func TestCertManagerBootstrapIssuesWhenNone(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	m, hashes := newCertTestManager(t, s3f, issuer)

	require.Equal(t, 1, issuer.calls)
	cert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// The attested fingerprint must describe the leaf actually served.
	served := certKeyHash(t, cert.Certificate[0])
	require.Equal(t, attestedHash(served), hashes.Serialize())

	// The lease is released, so a peer is not blocked behind us.
	require.Empty(t, s3f.currentETag(leaseObjectKey(certLeaseName)))
}

func TestCertManagerBootstrapAdoptsStoredCert(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	// A peer already issued for the fleet.
	store := newCertTestStore(s3f)
	certPEM := issueTestCertWithKey(t, "enclave.test", time.Now().Add(90*24*time.Hour), store.key)
	stored, err := store.SaveCert(context.Background(), certPEM, "")
	require.NoError(t, err)
	require.NotEmpty(t, stored.etag)

	m, hashes := newCertTestManagerForStore(t, store, issuer)

	require.Zero(t, issuer.calls, "a stored certificate must not trigger an order")
	// Adopting must record the version too, or the first poll re-downloads a
	// certificate we already hold.
	require.Equal(t, stored.etag, m.currentETag())
	cert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	served := certKeyHash(t, cert.Certificate[0])
	require.Equal(t, attestedHash(served), hashes.Serialize())
}

// The headline case: an enclave whose lease lapsed while it was descheduled
// resumes and tries to commit. Its captured ETag is stale, so the conditional
// write must reject it and it must adopt the peer's certificate instead of
// overwriting — otherwise the peer is left serving a leaf nobody else has.
func TestCertManagerZombieWriteIsRejected(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()

	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	store := newCertTestStore(s3f)

	// This enclave observes an empty store, so its write is create-only.
	var peerLeaf [sha256.Size]byte
	var peerKeyHash [sha256.Size]byte
	issuer.onIssue = func() {
		// While our order runs, a peer takes over and commits its own.
		peerCert := issueTestCertWithKey(
			t,
			"enclave.test",
			time.Now().Add(90*24*time.Hour),
			store.key,
		)
		_, err := store.SaveCert(ctx, peerCert, "")
		require.NoError(t, err)

		block, _ := pem.Decode(peerCert)
		require.NotNil(t, block)
		peerLeaf = sha256.Sum256(block.Bytes)
		peerKeyHash = certKeyHash(t, block.Bytes)
	}

	m, hashes := newCertTestManagerForStore(t, store, issuer)

	// The store must still hold the peer's certificate: ours was rejected.
	stored, err := store.LoadCert(ctx)
	require.NoError(t, err)
	require.Equal(t, peerLeaf, sha256.Sum256(stored.cert.Certificate[0]),
		"a stale ETag must not overwrite the peer's certificate")

	// And we must serve — and attest — the peer's leaf, not our orphaned one.
	cert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, peerLeaf, sha256.Sum256(cert.Certificate[0]))
	require.Equal(t, attestedHash(peerKeyHash), hashes.Serialize())

	require.Equal(t, 1, issuer.calls, "a rejected write must not re-run the order")
}

func TestCertManagerRenewSkipsWhenLeaseIsUnavailable(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}

	store := newCertTestStore(s3f)
	certPEM := issueTestCertWithKey(t, "enclave.test", time.Now().Add(90*24*time.Hour), store.key)
	_, err := store.SaveCert(context.Background(), certPEM, "")
	require.NoError(t, err)

	m, _ := newCertTestManagerForStore(t, store, issuer)

	writeLeaseDoc(t, s3f, leaseObjectKey(certLeaseName), time.Now().Add(time.Hour))

	renewed, err := m.renewUnderLease(context.Background(), "")
	require.NoError(t, err)

	require.Nil(t, renewed, "a peer holding the lease yields no new bundle")
	require.Zero(t, issuer.calls, "the lease holder is already renewing")
}

func TestCertManagerAdoptsPeerRenewalOnPoll(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	m, _ := newCertTestManager(t, s3f, issuer)

	first, err := m.GetCertificate(nil)
	require.NoError(t, err)

	// A peer renews out from under us.
	peerCert := issueTestCertWithKey(
		t,
		"enclave.test",
		time.Now().Add(90*24*time.Hour),
		m.store.key,
	)
	_, err = m.store.SaveCert(ctx, peerCert, m.currentETag())
	require.NoError(t, err)

	require.NoError(t, m.tick(ctx))

	got, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.NotEqual(t, first.Certificate[0], got.Certificate[0], "poll must adopt the peer's cert")
	require.Equal(t, 1, issuer.calls, "adopting must not trigger an order")
}

func TestRoutineRenewalKeepsFleetTLSIdentity(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{
		t:        t,
		cn:       "enclave.test",
		notAfter: time.Now().Add(time.Hour),
	}
	m, hashes := newCertTestManager(t, s3f, issuer)

	before, err := m.GetCertificate(nil)
	require.NoError(t, err)
	beforeDER := append([]byte(nil), before.Certificate[0]...)
	beforeKeyHash := certKeyHash(t, beforeDER)
	beforeAttestation := append([]byte(nil), hashes.Serialize()...)

	require.NoError(t, m.tick(context.Background()))

	after, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.NotEqual(t, beforeDER, after.Certificate[0], "renewal must install a new certificate")
	require.Equal(t, beforeKeyHash, certKeyHash(t, after.Certificate[0]),
		"routine renewal must reuse the fleet TLS key")
	require.Equal(t, beforeAttestation, hashes.Serialize(),
		"certificate renewal must not change the attested fleet identity")
	require.Equal(t, 2, issuer.calls)
}

func TestFleetKeepsOneIdentityWhilePeerHasNotAdoptedRenewal(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{
		t:        t,
		cn:       "enclave.test",
		notAfter: time.Now().Add(time.Hour),
	}
	key := newTestTLSKey(t)
	renewerStore := newCertStore(
		s3f,
		&dek{key: make([]byte, 32)},
		key,
		certTestBucket,
		"enclave.test",
	)
	peerStore := newCertStore(s3f, &dek{key: make([]byte, 32)}, key, certTestBucket, "enclave.test")
	renewer, renewerHashes := newCertTestManagerForStore(t, renewerStore, issuer)
	peer, peerHashes := newCertTestManagerForStore(t, peerStore, issuer)

	oldCert, err := peer.GetCertificate(nil)
	require.NoError(t, err)
	require.NoError(t, renewer.tick(context.Background()))
	newCert, err := renewer.GetCertificate(nil)
	require.NoError(t, err)

	require.NotEqual(t, oldCert.Certificate[0], newCert.Certificate[0],
		"the peer intentionally has not polled and still serves the old certificate")
	require.Equal(t,
		certKeyHash(t, oldCert.Certificate[0]),
		certKeyHash(t, newCert.Certificate[0]),
		"old and renewed certificates must carry the same fleet public key",
	)
	require.Equal(t, peerHashes.Serialize(), renewerHashes.Serialize(),
		"attestation from either side of the rollout must publish one identity")
}

func TestCertStoreSaveIsConditional(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertTestStore(s3f)

	certPEM := issueTestCertWithKey(t, "enclave.test", time.Now().Add(24*time.Hour), store.key)
	saved, err := store.SaveCert(ctx, certPEM, "")
	require.NoError(t, err)
	require.NotEmpty(t, saved.etag)

	// Create-only against an existing object must fail.
	_, err = store.SaveCert(ctx, certPEM, "")
	require.ErrorIs(t, err, errCertChanged)

	// The current ETag must succeed.
	_, err = store.SaveCert(ctx, certPEM, saved.etag)
	require.NoError(t, err)
}

// A peer deleting the object mid-write is the same "adopt what is there now"
// case as a peer rewriting it: S3 answers the conditional write with 404.
func TestSaveCertReportsChangedWhenObjectDeletedMidWrite(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertTestStore(s3f)

	certPEM := issueTestCertWithKey(t, "enclave.test", time.Now().Add(24*time.Hour), store.key)
	saved, err := store.SaveCert(ctx, certPEM, "")
	require.NoError(t, err)

	s3f.beforePut = func(key string) { delete(s3f.objects, key) }

	_, err = store.SaveCert(ctx, certPEM, saved.etag)

	require.ErrorIs(t, err, errCertChanged)
}

func TestCertStoreRoundTripsThroughDEK(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertTestStore(s3f)

	notAfter := time.Now().Add(42 * time.Hour).Truncate(time.Second)
	certPEM := issueTestCertWithKey(t, "enclave.test", notAfter, store.key)
	_, err := store.SaveCert(ctx, certPEM, "")
	require.NoError(t, err)

	// The object on the wire must not contain the certificate in the clear.
	raw := s3f.latestBody(store.certObjectKey())
	require.NotContains(t, string(raw), "BEGIN CERTIFICATE")

	bundle, err := store.LoadCert(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bundle.etag, "the bundle must carry the version it came from")
	require.Equal(t, notAfter.UTC(), bundle.notAfter.UTC())
}

func TestCertStoreMissingObject(t *testing.T) {
	setCertTestEnv(t)
	store := newCertTestStore(newFakeS3())

	bundle, err := store.LoadCert(context.Background())
	require.NoError(t, err)
	require.Nil(t, bundle)
}

func TestLoadOrCreateAccountKeyConvergesOnOne(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertTestStore(s3f)

	first, err := store.LoadOrCreateAccountKey(ctx)
	require.NoError(t, err)

	// A second enclave must adopt the stored key, not register its own account.
	second, err := store.LoadOrCreateAccountKey(ctx)
	require.NoError(t, err)
	require.Equal(t, first.Public(), second.Public())
}

func TestCertManagerIssueFailurePropagates(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test", err: errors.New("CA unavailable")}
	m, _, err := tryNewCertTestManager(s3f, issuer)

	require.Nil(t, m, "a manager must not exist without a certificate")
	require.ErrorContains(t, err, "CA unavailable")
	require.Empty(t, s3f.currentETag(leaseObjectKey(certLeaseName)), "lease must be released")
}

// The attested hash and the served certificate must never disagree: a client
// that reads user_data and then opens a connection pins one against the other.
// They are one atomic load, so this holds at every point of a renewal.
func TestAttestedHashAlwaysMatchesServedLeaf(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	ctx := context.Background()

	require.Equal(
		t,
		attestedHash([sha256.Size]byte{}),
		(&AttestationHashes{}).Serialize(),
	)

	m, hashes := newCertTestManager(t, s3f, issuer)

	attested := func() [sha256.Size]byte {
		var h [sha256.Size]byte
		copy(h[:], hashes.Serialize()[len(hashPrefix):])
		return h
	}
	served := func() [sha256.Size]byte {
		cert, err := m.GetCertificate(nil)
		require.NoError(t, err)
		return certKeyHash(t, cert.Certificate[0])
	}
	require.Equal(t, served(), attested(), "after bootstrap")

	// Adopting a peer's certificate moves both together too.
	beforeIdentity := served()
	beforeCert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	beforeDER := append([]byte(nil), beforeCert.Certificate[0]...)
	certPEM := issueTestCertWithKey(t, "enclave.test", time.Now().Add(90*24*time.Hour), m.store.key)
	bundle, err := m.store.SaveCert(ctx, certPEM, m.currentETag())
	require.NoError(t, err)
	m.currentCert.Store(bundle)

	require.NotEqual(
		t,
		beforeDER,
		bundle.cert.Certificate[0],
		"the served leaf should have changed",
	)
	require.Equal(t, beforeIdentity, served(), "the fleet identity should remain stable")
	require.Equal(t, served(), attested(), "after adopting a peer's certificate")
}

// S3 returns 409 ConditionalRequestConflict when concurrent conditional writes
// race internally. It is not contention with a peer, but the response is the
// same as 412: adopt what is there rather than reporting a broken issuance and
// burning another duplicate-certificate slot on a retry.
func TestCertStoreConditionalConflictIsCertChanged(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	dek := &dek{key: make([]byte, 32)}
	store := newCertStore(s3f, dek, newTestTLSKey(t), certTestBucket, "enclave.test")
	certPEM := issueTestCertWithKey(t, "enclave.test", time.Now().Add(90*24*time.Hour), store.key)

	s3f.putConflicts = 1
	_, err := store.SaveCert(context.Background(), certPEM, "")
	require.ErrorIs(t, err, errCertChanged,
		"a 409 must surface as cert-changed so the caller adopts instead of failing")
}

// HeadObject can see a version GetObject then misses, if the object is deleted
// in between. The enclave keeps serving what it has rather than dropping its
// certificate, and must not do so silently.
func TestCertManagerTickSurvivesVanishedCert(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	m, _ := newCertTestManager(t, s3f, issuer)
	ctx := context.Background()
	served := m.currentCert.Load()
	require.NotNil(t, served)

	// The object is deleted out from under the fleet.
	s3f.getMissing = map[string]bool{m.store.certObjectKey(): true}

	require.NoError(t, m.tick(ctx), "a vanished object must not fail the poll")
	require.Same(t, served, m.currentCert.Load(), "the previous certificate stays in service")
}
