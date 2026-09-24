package runtime

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

type migrationControlMigrator struct {
	previous     *PreviousPCR0Info
	previousErr  error
	status       *MigrationStatus
	statusErr    error
	candidate    *CandidateInfo
	candidateErr error
}

func (m *migrationControlMigrator) RunPredecessorHandoff(
	context.Context, PrimaryKMS, DEK, []StaticSecret, crypto.Signer,
) {
}

func (m *migrationControlMigrator) AwaitCandidateHandoff(context.Context) error { return nil }

func (m *migrationControlMigrator) PreviousPCR0Info(context.Context) (*PreviousPCR0Info, error) {
	return m.previous, m.previousErr
}

func (m *migrationControlMigrator) MigrationStatus(context.Context) (*MigrationStatus, error) {
	return m.status, m.statusErr
}

func (m *migrationControlMigrator) CandidateInfo(context.Context) (*CandidateInfo, error) {
	return m.candidate, m.candidateErr
}

func (m *migrationControlMigrator) MigrationIntentBucket() string {
	return migrationIntentTestBucket
}

func TestServersStartReturnsBindErrors(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	t.Run("private", func(t *testing.T) {
		s := &servers{
			cfg: testCfg,
			int: &http.Server{Addr: occupied.Addr().String()},
			ext: &http.Server{},
			rt:  newRuntimeState(),
		}
		err := s.Start(context.Background(), Config{})
		require.ErrorContains(t, err, "private listener")
	})

	t.Run("public", func(t *testing.T) {
		port := occupied.Addr().(*net.TCPAddr).Port
		ipv6, _ := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port))
		if ipv6 != nil {
			defer func() { _ = ipv6.Close() }()
		}
		s := &servers{
			cfg: testCfg,
			int: &http.Server{Addr: "127.0.0.1:0"},
			ext: &http.Server{},
			rt:  newRuntimeState(),
		}
		err := s.Start(context.Background(), Config{ExtPort: uint16(port)})
		require.ErrorContains(t, err, "public listener")
	})
}

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name     string
		ready    bool
		wantCode int
		wantBody string
	}{
		{"initializing", false, http.StatusServiceUnavailable, `{"status":"initializing"}`},
		{"ready", true, http.StatusOK, `{"status":"ready"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntimeState()
			if tc.ready {
				rt.NotifyReady()
			}

			rr := httptest.NewRecorder()
			healthHandler(rt).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

			if rr.Code != tc.wantCode {
				t.Fatalf("status: got %d, want %d", rr.Code, tc.wantCode)
			}
			require.JSONEq(t, tc.wantBody, rr.Body.String())
		})
	}
}

func TestWithTokenAuth(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		auth       string
		wantCode   int
		wantCalled bool
	}{
		{"disabled", "", "", http.StatusOK, true},
		{"missing", "secret", "", http.StatusUnauthorized, false},
		{"bad format", "secret", "Token secret", http.StatusUnauthorized, false},
		{"wrong token", "secret", "Bearer wrong", http.StatusForbidden, false},
		{"valid", "secret", "Bearer secret", http.StatusOK, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := withTokenAuth(tc.token, func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			h.ServeHTTP(rr, req)

			if rr.Code != tc.wantCode {
				t.Fatalf("status: got %d, want %d", rr.Code, tc.wantCode)
			}
			if called != tc.wantCalled {
				t.Fatalf("handler called: got %v, want %v", called, tc.wantCalled)
			}
		})
	}
}

func TestCorsWildcard(t *testing.T) {
	t.Run("preflight", func(t *testing.T) {
		called := false
		h := corsWildcard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodOptions, "/enclave/v1/info", nil))

		if rr.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusNoContent)
		}
		if called {
			t.Fatal("preflight called next handler")
		}
		assertCORSHeaders(t, rr.Header())
	})

	t.Run("normal request", func(t *testing.T) {
		h := corsWildcard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
		}))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))

		if rr.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusCreated)
		}
		assertCORSHeaders(t, rr.Header())
	})
}

func TestAttestationHandler(t *testing.T) {
	t.Run("missing nonce", func(t *testing.T) {
		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{}}, &AttestationHashes{}).ServeHTTP(rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation", nil))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("bad nonce", func(t *testing.T) {
		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{}}, &AttestationHashes{}).ServeHTTP(rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation?nonce=not-hex", nil))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("returns document bound to nonce and user data", func(t *testing.T) {
		doc := []byte("attestation document")
		session := &fakeNSMSession{responses: []response.Response{attestationDocumentResponse(doc)}}
		hashes := &AttestationHashes{}
		tlsHash := sha256.Sum256([]byte("tls"))
		hashes.SetTLSKeyHashSource(staticKeyHash(tlsHash))
		rawNonce := bytes.Repeat([]byte{0xab}, nonceNumDigits/2)

		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{session: session}}, hashes).ServeHTTP(
			rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation?nonce="+hex.EncodeToString(rawNonce), nil),
		)

		if rr.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusOK)
		}
		if rr.Body.String() != base64.StdEncoding.EncodeToString(doc)+"\n" {
			t.Fatalf("body: got %q", rr.Body.String())
		}
		if len(session.requests) != 1 {
			t.Fatalf("nsm requests: got %d, want 1", len(session.requests))
		}
		req, ok := session.requests[0].(*request.Attestation)
		if !ok {
			t.Fatalf("nsm request type: %T", session.requests[0])
		}
		if !bytes.Equal(req.Nonce, rawNonce) {
			t.Fatalf("nonce: got %x, want %x", req.Nonce, rawNonce)
		}
		if !bytes.Equal(req.UserData, hashes.Serialize()) {
			t.Fatalf("user_data: got %x, want %x", req.UserData, hashes.Serialize())
		}
		require.Len(t, req.UserData, 39)
	})
}

func TestConfigureEnclaveInfoHandler(t *testing.T) {
	ctx := context.Background()
	ownPCR0 := strings.Repeat("ab", 48)
	ssm := NewSSM(&fakeSSM{params: map[string]string{
		testCfg.migrationPreviousPCR0Param(ownPCR0):            "previous",
		testCfg.migrationPreviousPCR0AttestationParam(ownPCR0): "attestation",
	}})
	rt := newRuntimeState()
	s := &servers{cfg: testCfg, rm: http.NewServeMux(), rt: rt}
	nsm := &nsmW{nsm: &fakeNSM{session: newStatefulNSMSession(t, map[uint][]byte{
		0: bytes.Repeat([]byte{0xab}, 48),
	})}}
	migrator, err := NewMigrator(testCfg, nsm, ssm, newFakeS3(), migrationIntentTestBucket)
	require.NoError(t, err)

	ancestry := &stubAncestry{snap: &AncestryInfo{
		Generations: []AncestorGeneration{{
			PCR0:  strings.Repeat("cd", 48),
			KeyID: "key-1",
			State: keyStateDeleted,
		}},
		Complete:  true,
		CheckedAt: &ancestryTestCheckedAt,
	}}

	require.NoError(t, s.ConfigureEnclaveInfoHandler(migrator))

	serve := func(t *testing.T) []byte {
		t.Helper()
		rr := httptest.NewRecorder()
		s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))
		require.Equal(t, http.StatusOK, rr.Code)
		return rr.Body.Bytes()
	}
	want := func(t *testing.T, status string, ancestryInfo *AncestryInfo) string {
		t.Helper()
		body, err := json.Marshal(RuntimeInfo{
			Version:                  Version,
			Status:                   status,
			PreviousPCR0:             "previous",
			PreviousPCR0Attestation:  "attestation",
			MigrationCooldownSeconds: int(testCfg.MigrationCooldown.Seconds()),
			MigrationIntentBucket:    migrationIntentTestBucket,
			Migration: &MigrationStatus{
				State: migrationStateNone, SourcePCR0: strings.Repeat("ab", 48),
			},
			UpstreamApp:  rt.UpstreamAppInfo(),
			KMSKeyLocked: testCfg.KMSLocked,
			Ancestry:     ancestryInfo,
		})
		require.NoError(t, err)
		return string(body)
	}

	// Candidates have no lineage to audit.
	require.JSONEq(t, want(t, runtimeStatusCandidate, nil), string(serve(t)))

	rt.NotifyStarting()
	s.SetAncestry(ctx, ancestry)
	require.True(t, ancestry.started, "setting the audit must start its refresh lifecycle")
	require.JSONEq(t, want(t, runtimeStatusStarting, ancestry.snap), string(serve(t)))

	rt.NotifyReady()
	body := serve(t)
	require.JSONEq(t, want(t, runtimeStatusReady, ancestry.snap), string(body))

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &got))
	require.NotContains(t, got, "attestation_pubkey")
}

func TestConfigureEnclaveInfoHandlerReportsInboundHandoff(t *testing.T) {
	requestedAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rt := newRuntimeState()
	s := &servers{cfg: testCfg, rm: http.NewServeMux(), rt: rt}
	inbound := &CandidateInfo{
		AwaitingHandoffFrom: strings.Repeat("ab", 48), RequestedAt: &requestedAt,
	}
	migrator := &migrationControlMigrator{
		previous:  &PreviousPCR0Info{PCR0: "genesis"},
		status:    &MigrationStatus{State: migrationStateNone},
		candidate: inbound,
	}
	require.NoError(t, s.ConfigureEnclaveInfoHandler(migrator))

	serve := func(t *testing.T) RuntimeInfo {
		t.Helper()
		rr := httptest.NewRecorder()
		s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))
		require.Equal(t, http.StatusOK, rr.Code)
		var got RuntimeInfo
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
		return got
	}

	got := serve(t)
	require.Equal(t, runtimeStatusCandidate, got.Status)
	require.Equal(t, inbound, got.Candidate)

	// A candidate that cannot read the intent log is still a candidate.
	migrator.candidate, migrator.candidateErr = nil, errors.New("s3 unavailable")
	got = serve(t)
	require.Equal(t, runtimeStatusCandidate, got.Status)
	require.Nil(t, got.Candidate)

	// Only candidates report inbound handoffs.
	migrator.candidate, migrator.candidateErr = inbound, nil
	rt.NotifyStarting()
	got = serve(t)
	require.Equal(t, runtimeStatusStarting, got.Status)
	require.Nil(t, got.Candidate, "only a candidate reports an inbound handoff")
}

var ancestryTestCheckedAt = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

type stubAncestry struct {
	snap    *AncestryInfo
	started bool
}

func (s *stubAncestry) Start(context.Context) { s.started = true }

func (s *stubAncestry) Snapshot() *AncestryInfo { return s.snap }

// A caller that wires no audit must get no audit block, rather than an empty one
// that reads as "every ancestor key is accounted for".
func TestConfigureEnclaveInfoHandlerOmitsAncestryWhenUnset(t *testing.T) {
	s, migrator := enclaveInfoTestServer(t)
	require.NoError(t, s.ConfigureEnclaveInfoHandler(migrator))

	rr := httptest.NewRecorder()
	s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotContains(t, rr.Body.String(), "ancestry")
}

// A blind audit must still serve.
func TestConfigureEnclaveInfoHandlerServesUnknownAncestry(t *testing.T) {
	s, migrator := enclaveInfoTestServer(t)
	ancestry := &stubAncestry{snap: &AncestryInfo{
		Generations: []AncestorGeneration{{
			PCR0:  strings.Repeat("cd", 48),
			KeyID: "key-1",
			State: keyStateUnknown,
		}},
		CheckedAt: &ancestryTestCheckedAt,
	}}
	require.NoError(t, s.ConfigureEnclaveInfoHandler(migrator))
	s.SetAncestry(context.Background(), ancestry)

	rr := httptest.NewRecorder()
	s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `"state":"unknown"`)
	require.NotContains(t, rr.Body.String(), keyStateDeleted)
}

// A KMS that answers nothing must cost the endpoint nothing.
func TestConfigureEnclaveInfoHandlerSurvivesABlindAudit(t *testing.T) {
	s, migrator := enclaveInfoTestServer(t)
	kms := newFakeKMS()
	kms.describeErr = errors.New("kms unreachable")
	p0, p1, p2 := ancestryPCR0(1), ancestryPCR0(2), ancestryPCR0(3)
	fx := newAncestryFixture(
		t, testSnapshot(p2, "key-2", p1, "key-1"), &kmsW{cfg: testCfg, kms: kms},
	)
	fx.storeOriginReceipt(t, testSnapshot(p1, "key-1", p0, "key-0"))
	fx.storeOriginReceipt(t, testSnapshot(p0, "key-0", "", ""))
	ancestry := fx.a
	ancestry.refresh(context.Background())

	require.NoError(t, s.ConfigureEnclaveInfoHandler(migrator))
	s.SetAncestry(context.Background(), ancestry)
	rr := httptest.NewRecorder()
	s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	var got RuntimeInfo
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Ancestry.Generations, 2)
	for _, gen := range got.Ancestry.Generations {
		require.Equal(t, keyStateUnknown, gen.State)
	}
}

func enclaveInfoTestServer(t *testing.T) (*servers, Migrator) {
	t.Helper()

	s := &servers{
		cfg: testCfg,
		rm:  http.NewServeMux(),
		rt:  newRuntimeState(),
	}
	nsm := &nsmW{nsm: &fakeNSM{session: newStatefulNSMSession(t, map[uint][]byte{
		0: bytes.Repeat([]byte{0xab}, 48),
	})}}
	migrator, err := NewMigrator(
		testCfg, nsm, NewSSM(&fakeSSM{}), newFakeS3(), migrationIntentTestBucket,
	)
	require.NoError(t, err)
	return s, migrator
}

func TestConfigureEnclaveInfoHandlerFailsClosedOnStatusError(t *testing.T) {
	statusErr := fmt.Errorf("S3 unavailable: %w", errMigrationIntentStoreUnavailable)
	s := &servers{cfg: testCfg, rm: http.NewServeMux()}
	migrator := &migrationControlMigrator{statusErr: statusErr}
	require.NoError(t, s.ConfigureEnclaveInfoHandler(migrator))

	rr := httptest.NewRecorder()
	s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))

	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	require.Contains(t, rr.Body.String(), statusErr.Error())
}

func assertCORSHeaders(t *testing.T, h http.Header) {
	t.Helper()

	for _, name := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Expose-Headers",
	} {
		if h.Get(name) != "*" {
			t.Fatalf("%s: got %q, want *", name, h.Get(name))
		}
	}
	if h.Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("Access-Control-Max-Age: got %q, want 600", h.Get("Access-Control-Max-Age"))
	}
}

func TestExternalMuxSeparatesRuntimeAndApplicationRoutes(t *testing.T) {
	var proxied []string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer app.Close()

	appURL, err := url.Parse(app.URL)
	require.NoError(t, err)

	rt := newRuntimeState()
	s := SetupHttpServers(
		rt,
		Config{AppWebSrv: appURL},
		&nsmW{},
		NewTelemetry(testCfg, nil),
		&AttestationHashes{},
		"token",
	).(*servers)
	require.NoError(t, s.ConfigureEnclaveInfoHandler(&migrationControlMigrator{
		previous: &PreviousPCR0Info{},
		status:   &MigrationStatus{},
	}))

	unavailable := func(t *testing.T) {
		nonce := strings.Repeat("ab", nonceNumDigits/2)
		for _, path := range []string{"/anything", "/enclave/attestation?nonce=" + nonce} {
			rr := httptest.NewRecorder()
			s.em.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			require.Equal(t, http.StatusServiceUnavailable, rr.Code, path)
		}
		require.Empty(t, proxied, "nothing may be proxied before the app starts")
	}
	t.Run("a candidate serves no application and no attestation", unavailable)
	rt.NotifyStarting()
	t.Run("nor does a starting runtime", unavailable)

	rt.NotifyReady()

	t.Run("application routes reach the proxy", func(t *testing.T) {
		for _, route := range []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/v1/info"},
			{http.MethodOptions, "/v1/orders"},
			{http.MethodPost, "/v1/metrics"},
			{http.MethodPost, "/v1/logs"},
			{http.MethodPost, "/v1/traces"},
			{http.MethodGet, "/enclavex/v1"},
			{http.MethodGet, "/anything"},
		} {
			rr := httptest.NewRecorder()
			s.em.ServeHTTP(rr, httptest.NewRequest(route.method, route.path, nil))
			require.Equal(t, http.StatusOK, rr.Code, "%s %s", route.method, route.path)
			require.Contains(t, proxied, route.path)
		}
	})

	t.Run("runtime routes are handled by the runtime", func(t *testing.T) {
		for _, route := range []struct {
			method string
			path   string
			status int
		}{
			{http.MethodGet, "/enclave/v1/info", http.StatusOK},
			// A ready request still requires a nonce.
			{http.MethodGet, "/enclave/attestation", http.StatusBadRequest},
			{http.MethodGet, "/enclave/v1/metrics", http.StatusNotFound},
			{http.MethodGet, "/enclave/v1/logs", http.StatusNotFound},
			{http.MethodGet, "/enclave/v1/traces", http.StatusNotFound},
			{http.MethodPost, "/enclave/v1/metrics", http.StatusNotFound},
			{http.MethodPost, "/enclave/v1/logs", http.StatusNotFound},
			{http.MethodPost, "/enclave/v1/traces", http.StatusNotFound},
		} {
			rr := httptest.NewRecorder()
			s.em.ServeHTTP(rr, httptest.NewRequest(route.method, route.path, nil))
			require.Equal(t, route.status, rr.Code, "%s %s", route.method, route.path)
			require.NotContains(t, proxied, route.path)
			assertCORSHeaders(t, rr.Header())
		}
	})

	t.Run("runtime namespace handles preflight and rejects unknown routes", func(t *testing.T) {
		for _, path := range []string{
			"/enclave/v1/info",
			"/enclave/v1/metrics",
			"/enclave/v1/logs",
			"/enclave/v1/traces",
		} {
			rr := httptest.NewRecorder()
			s.em.ServeHTTP(rr, httptest.NewRequest(http.MethodOptions, path, nil))
			require.Equal(t, http.StatusNoContent, rr.Code, path)
			assertCORSHeaders(t, rr.Header())
		}

		for _, route := range []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/enclave/unknown"},
			{http.MethodGet, "/enclave/v1ish"},
			{http.MethodGet, "/enclave/v1/unknown"},
		} {
			rr := httptest.NewRecorder()
			s.em.ServeHTTP(rr, httptest.NewRequest(route.method, route.path, nil))
			require.Equal(t, http.StatusNotFound, rr.Code, "%s %s", route.method, route.path)
			require.NotContains(t, proxied, route.path)
		}

		rr := httptest.NewRecorder()
		s.em.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/enclave", nil))

		require.Contains(t, []int{
			http.StatusMovedPermanently,
			http.StatusTemporaryRedirect,
		}, rr.Code)
		require.Equal(t, "/enclave/", rr.Header().Get("Location"))
		require.NotContains(t, proxied, "/enclave")
	})
}
