package runtime

import (
	"context"
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

// issueTestCert mints a self-signed leaf standing in for a CA-issued one.
func issueTestCert(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
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

func (f *fakeIssuer) Issue(context.Context, string) ([]byte, []byte, error) {
	f.calls++
	if f.onIssue != nil {
		f.onIssue()
	}
	if f.err != nil {
		return nil, nil, f.err
	}
	notAfter := f.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	certPEM, keyPEM := issueTestCert(f.t, f.cn, notAfter)
	return certPEM, keyPEM, nil
}

// attestedHash is user_data for a leaf before a response-signing key is set.
func attestedHash(leaf [sha256.Size]byte) []byte {
	payload := append([]byte(hashPrefix), leaf[:]...)
	payload = append(payload, hashSeparator...)
	payload = append(payload, hashPrefix...)
	return append(payload, make([]byte, sha256.Size)...)
}

func newCertTestStore(s3f *fakeS3) *certStore {
	return newCertStore(s3f, &dek{key: make([]byte, 32)}, certTestBucket, "enclave.test")
}

func tryNewCertTestManager(s3f *fakeS3, issuer certIssuer) (*certManager, AttestationHashes, error) {
	hashes := NewAttestationHashes()
	m, err := newCertManager(
		context.Background(), newCertTestStore(s3f), issuer,
		s3f, certTestBucket, "enclave.test", hashes,
	)
	return m, hashes, err
}

func newCertTestManager(t *testing.T, s3f *fakeS3, issuer certIssuer) (*certManager, AttestationHashes) {
	t.Helper()
	m, hashes, err := tryNewCertTestManager(s3f, issuer)
	require.NoError(t, err)
	return m, hashes
}

func TestCertManagerBootstrapIssuesWhenFleetHasNone(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	m, hashes := newCertTestManager(t, s3f, issuer)

	require.Equal(t, 1, issuer.calls)
	cert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// The attested fingerprint must describe the leaf actually served.
	served := sha256.Sum256(cert.Certificate[0])
	require.Equal(t, attestedHash(served), hashes.Serialize())

	// The lease is released, so a peer is not blocked behind us.
	require.Empty(t, s3f.currentETag(leaseObjectKey(certLeaseName)))
}

func TestCertManagerBootstrapAdoptsStoredCert(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}
	// A peer already issued for the fleet.
	certPEM, keyPEM := issueTestCert(t, "enclave.test", time.Now().Add(90*24*time.Hour))
	stored, err := newCertTestStore(s3f).SaveCert(context.Background(), certPEM, keyPEM, "")
	require.NoError(t, err)
	require.NotEmpty(t, stored.etag)

	m, hashes := newCertTestManager(t, s3f, issuer)

	require.Zero(t, issuer.calls, "a stored certificate must not trigger an order")
	// Adopting must record the version too, or the first poll re-downloads a
	// certificate we already hold.
	require.Equal(t, stored.etag, m.currentETag())
	cert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	served := sha256.Sum256(cert.Certificate[0])
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
	issuer.onIssue = func() {
		// While our order runs, a peer takes over and commits its own.
		peerCert, peerKey := issueTestCert(t, "enclave.test", time.Now().Add(90*24*time.Hour))
		_, err := store.SaveCert(ctx, peerCert, peerKey, "")
		require.NoError(t, err)

		block, _ := pem.Decode(peerCert)
		require.NotNil(t, block)
		peerLeaf = sha256.Sum256(block.Bytes)
	}

	m, hashes := newCertTestManager(t, s3f, issuer)

	// The store must still hold the peer's certificate: ours was rejected.
	stored, err := store.LoadCert(ctx)
	require.NoError(t, err)
	require.Equal(t, peerLeaf, sha256.Sum256(stored.cert.Certificate[0]),
		"a stale ETag must not overwrite the peer's certificate")

	// And we must serve — and attest — the peer's leaf, not our orphaned one.
	cert, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, peerLeaf, sha256.Sum256(cert.Certificate[0]))
	require.Equal(t, attestedHash(peerLeaf), hashes.Serialize())

	require.Equal(t, 1, issuer.calls, "a rejected write must not re-run the order")
}

func TestCertManagerRenewSkipsWhenPeerHoldsLease(t *testing.T) {
	setCertTestEnv(t)
	s3f := newFakeS3()
	issuer := &fakeIssuer{t: t, cn: "enclave.test"}

	certPEM, keyPEM := issueTestCert(t, "enclave.test", time.Now().Add(90*24*time.Hour))
	_, err := newCertTestStore(s3f).SaveCert(context.Background(), certPEM, keyPEM, "")
	require.NoError(t, err)

	m, _ := newCertTestManager(t, s3f, issuer)

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
	peerCert, peerKey := issueTestCert(t, "enclave.test", time.Now().Add(90*24*time.Hour))
	_, err = m.store.SaveCert(ctx, peerCert, peerKey, m.currentETag())
	require.NoError(t, err)

	require.NoError(t, m.tick(ctx))

	got, err := m.GetCertificate(nil)
	require.NoError(t, err)
	require.NotEqual(t, first.Certificate[0], got.Certificate[0], "poll must adopt the peer's cert")
	require.Equal(t, 1, issuer.calls, "adopting must not trigger an order")
}

func TestCertStoreSaveIsConditional(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertStore(s3f, &dek{key: make([]byte, 32)}, certTestBucket, "enclave.test")

	certPEM, keyPEM := issueTestCert(t, "enclave.test", time.Now().Add(24*time.Hour))
	saved, err := store.SaveCert(ctx, certPEM, keyPEM, "")
	require.NoError(t, err)
	require.NotEmpty(t, saved.etag)

	// Create-only against an existing object must fail.
	_, err = store.SaveCert(ctx, certPEM, keyPEM, "")
	require.ErrorIs(t, err, errCertChanged)

	// A stale ETag must fail.
	_, err = store.SaveCert(ctx, certPEM, keyPEM, `"etag-stale"`)
	require.ErrorIs(t, err, errCertChanged)

	// The current ETag must succeed.
	_, err = store.SaveCert(ctx, certPEM, keyPEM, saved.etag)
	require.NoError(t, err)
}

func TestCertStoreRoundTripsThroughDEK(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertStore(s3f, &dek{key: make([]byte, 32)}, certTestBucket, "enclave.test")

	notAfter := time.Now().Add(42 * time.Hour).Truncate(time.Second)
	certPEM, keyPEM := issueTestCert(t, "enclave.test", notAfter)
	_, err := store.SaveCert(ctx, certPEM, keyPEM, "")
	require.NoError(t, err)

	// The object on the wire must not contain the key in the clear.
	raw := s3f.latestBody(store.certObjectKey())
	require.NotContains(t, string(raw), "PRIVATE KEY")

	bundle, err := store.LoadCert(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bundle.etag, "the bundle must carry the version it came from")
	require.Equal(t, notAfter.UTC(), bundle.notAfter.UTC())
}

func TestCertStoreMissingObject(t *testing.T) {
	setCertTestEnv(t)
	store := newCertStore(newFakeS3(), &dek{key: make([]byte, 32)}, certTestBucket, "enclave.test")

	bundle, err := store.LoadCert(context.Background())
	require.NoError(t, err)
	require.Nil(t, bundle)
}

func TestLoadOrCreateAccountKeyConvergesOnOne(t *testing.T) {
	setCertTestEnv(t)
	ctx := context.Background()
	s3f := newFakeS3()
	store := newCertStore(s3f, &dek{key: make([]byte, 32)}, certTestBucket, "enclave.test")

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

	require.Equal(t,
		attestedHash([sha256.Size]byte{}),
		NewAttestationHashes().Serialize(),
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
		return sha256.Sum256(cert.Certificate[0])
	}
	require.Equal(t, served(), attested(), "after bootstrap")

	// Adopting a peer's certificate moves both together too.
	before := served()
	certPEM, keyPEM := issueTestCert(t, "enclave.test", time.Now().Add(90*24*time.Hour))
	bundle, err := m.store.SaveCert(ctx, certPEM, keyPEM, m.currentETag())
	require.NoError(t, err)
	m.currentCert.Store(bundle)

	require.NotEqual(t, before, served(), "the served leaf should have changed")
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
	store := newCertStore(s3f, dek, certTestBucket, "enclave.test")
	certPEM, keyPEM := issueTestCert(t, "enclave.test", time.Now().Add(90*24*time.Hour))

	s3f.putConflicts = 1
	_, err := store.SaveCert(context.Background(), certPEM, keyPEM, "")
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
