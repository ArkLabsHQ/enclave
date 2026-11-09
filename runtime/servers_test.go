package runtime

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ArkLabsHQ/enclave/internal/signing"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
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
	context.Context, PrimaryKMS, []byte, crypto.Signer,
) {
}

func (m *migrationControlMigrator) AwaitCandidateHandoff(context.Context) error { return nil }

func (m *migrationControlMigrator) SetSnapshot(Snapshot) {}

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
		exited   bool
		wantCode int
		wantBody string
	}{
		{"initializing", false, false, http.StatusServiceUnavailable, `{"status":"initializing"}`},
		{"ready", true, false, http.StatusOK, `{"status":"ready"}`},
		{
			"ready but exited",
			true,
			true,
			http.StatusServiceUnavailable,
			`{"status":"upstream_exited"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntimeState()
			if tc.ready {
				rt.NotifyReady()
			}
			if tc.exited {
				go func() { <-rt.ChildDone() }()
				rt.NotifyChildExit(errors.New("killed"))
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
		attestationHandler(&nsmW{nsm: &fakeNSM{}}, &AttestationData{}).ServeHTTP(rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation", nil))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("bad nonce", func(t *testing.T) {
		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{}}, &AttestationData{}).ServeHTTP(rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation?nonce=not-hex", nil))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("returns document bound to nonce and user data", func(t *testing.T) {
		doc := []byte("attestation document")
		session := &fakeNSMSession{responses: []response.Response{attestationDocumentResponse(doc)}}
		attData := &AttestationData{}
		tlsHash := sha256.Sum256([]byte("tls"))
		attData.SetTLSKeyHashSource(staticKeyHash(tlsHash))
		attData.SetMigrationSource(
			staticMigrationStatus(&MigrationStatus{State: migrationStateNone}, nil),
		)
		rawNonce := bytes.Repeat([]byte{0xab}, nonceNumDigits/2)

		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{session: session}}, attData).ServeHTTP(
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
		want, err := attData.UserData(context.Background())
		require.NoError(t, err)
		if !bytes.Equal(req.UserData, want) {
			t.Fatalf("user_data: got %x, want %x", req.UserData, want)
		}
		require.Len(t, req.UserData, 149)
	})

	t.Run("fails closed while the pending migration is unknown", func(t *testing.T) {
		nonce := strings.Repeat("ab", nonceNumDigits/2)
		unread := &AttestationData{}
		unreadable := &AttestationData{}
		unreadable.SetMigrationSource(
			staticMigrationStatus(nil, errors.New("intent log unavailable")),
		)
		for name, attData := range map[string]*AttestationData{
			"no source": unread, "source fails": unreadable,
		} {
			session := &fakeNSMSession{}
			rr := httptest.NewRecorder()
			attestationHandler(&nsmW{nsm: &fakeNSM{session: session}}, attData).ServeHTTP(rr,
				httptest.NewRequest(http.MethodGet, "/enclave/attestation?nonce="+nonce, nil))
			require.Equal(t, http.StatusInternalServerError, rr.Code, name)
			require.Empty(t, session.requests, "%s: nothing may be attested", name)
		}
	})
}

func TestConfigureEnclaveInfoHandler(t *testing.T) {
	ctx := context.Background()
	ssm := NewSSM(&fakeSSM{})
	rt := newRuntimeState()
	s := &servers{cfg: testCfg, rm: http.NewServeMux(), rt: rt}
	nsm := &nsmW{nsm: newFakeNSM(t).withPCRs(map[uint][]byte{
		0: bytes.Repeat([]byte{0xab}, 48),
	})}
	migrator, err := NewMigrator(testCfg, nsm, ssm, newFakeS3(), migrationIntentTestBucket)
	require.NoError(t, err)
	migrator.SetSnapshot(Snapshot{
		predecessorPCR0: "previous", transitionReceipt: "attestation",
	})

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
	fx.publish(t, testSnapshot(p1, "key-1", p0, "key-0"))
	fx.publish(t, testSnapshot(p0, "key-0", "", ""))
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
	nsm := &nsmW{nsm: newFakeNSM(t).withPCRs(map[uint][]byte{
		0: bytes.Repeat([]byte{0xab}, 48),
	})}
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

// The forwarders are reachable only on the internal listener. The external mux
// sends the same paths to the application, which the test below pins.
func TestInternalMuxRoutesOTLPToTheForwarders(t *testing.T) {
	up := newFakeOTLPEndpoints(t)
	appURL, err := url.Parse("http://127.0.0.1:1")
	require.NoError(t, err)
	s := SetupHttpServers(
		newRuntimeState(),
		Config{AppWebSrv: appURL},
		&nsmW{},
		NewTelemetry(testCfg, testAWS(t, newFakeCloudWatchLogs(), up.URL)),
		&AttestationData{},
		"token",
	).(*servers)

	for _, path := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		post := func(authorization string) int {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			if authorization != "" {
				req.Header.Set("Authorization", authorization)
			}
			rr := httptest.NewRecorder()
			s.int.Handler.ServeHTTP(rr, req)
			return rr.Code
		}

		require.Equal(t, http.StatusUnauthorized, post(""), "%s needs the runtime token", path)
		require.Empty(t, up.callsTo(path))
		require.Equal(t, http.StatusOK, post("Bearer token"), path)
		require.Len(t, up.callsTo(path), 1, "%s must reach its AWS endpoint", path)
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
		&AttestationData{},
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

type recordedSpans struct {
	spans []sdktrace.ReadOnlySpan
}

func (e *recordedSpans) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.spans = append(e.spans, spans...)
	return nil
}

func (e *recordedSpans) Shutdown(context.Context) error { return nil }

func (e *recordedSpans) named(t *testing.T, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, span := range e.spans {
		if span.Name() == name {
			return span
		}
	}
	require.Failf(t, "span not recorded", "%q", name)
	return nil
}

func spanAttributes(span sdktrace.ReadOnlySpan) map[string]string {
	attrs := map[string]string{}
	for _, kv := range span.Attributes() {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	return attrs
}

func TestRuntimeSpans(t *testing.T) {
	const (
		callerTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
		callerSpanID  = "00f067aa0ba902b7"
		callerParent  = "00-" + callerTraceID + "-" + callerSpanID + "-01"
	)

	var received http.Header
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer app.Close()
	appURL, err := url.Parse(app.URL)
	require.NoError(t, err)

	recorded := &recordedSpans{}
	previous := otel.GetTracerProvider()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(recorded))
	otel.SetTracerProvider(provider)
	// The global delegate keeps pointing at provider after previous is restored,
	// so shut it down to stop later tests' spans reaching recorded.
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	setup := func(t *testing.T, traced bool, rt *runtimeState) *servers {
		t.Helper()
		s := SetupHttpServers(
			rt,
			Config{AppWebSrv: appURL, ExportTraces: traced},
			&nsmW{},
			NewTelemetry(testCfg, nil),
			&AttestationData{},
			"token",
		).(*servers)
		require.NoError(t, s.ConfigureEnclaveInfoHandler(&migrationControlMigrator{
			previous: &PreviousPCR0Info{},
			status:   &MigrationStatus{},
		}))
		return s
	}
	ready := func() *runtimeState {
		rt := newRuntimeState()
		rt.NotifyReady()
		return rt
	}
	serve := func(s *servers, r *http.Request) *httptest.ResponseRecorder {
		recorded.spans = nil
		rr := httptest.NewRecorder()
		s.em.ServeHTTP(rr, r)
		return rr
	}
	fromCaller := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/orders/42?token=secret", nil)
		r.Header.Set("Traceparent", callerParent)
		r.Header.Set("Tracestate", "vendor=secret")
		r.Header.Set("User-Agent", "secret-agent")
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		return r
	}

	t.Run("does nothing unless traces are exported", func(t *testing.T) {
		rr := serve(setup(t, false, ready()), fromCaller())

		require.Equal(t, http.StatusOK, rr.Code)
		require.Empty(t, recorded.spans)
		require.Equal(t, callerParent, received.Get("Traceparent"))
		require.Equal(t, "vendor=secret", received.Get("Tracestate"))
	})

	t.Run("a proxied request is a new root that only links the caller", func(t *testing.T) {
		rr := serve(setup(t, true, ready()), fromCaller())
		require.Equal(t, http.StatusOK, rr.Code)
		require.Len(t, recorded.spans, 2)

		proxy := recorded.named(t, "proxy")
		require.Equal(t, trace.SpanKindServer, proxy.SpanKind())
		require.False(t, proxy.Parent().IsValid())
		require.NotEqual(t, callerTraceID, proxy.SpanContext().TraceID().String())
		require.Len(t, proxy.Links(), 1)
		link := proxy.Links()[0].SpanContext
		require.Equal(t, callerTraceID, link.TraceID().String())
		require.Equal(t, callerSpanID, link.SpanID().String())
		require.Empty(t, link.TraceState().String(), "tracestate must not reach X-Ray")

		upstream := recorded.named(t, "upstream")
		require.Equal(t, trace.SpanKindClient, upstream.SpanKind())
		require.Equal(t, proxy.SpanContext().TraceID(), upstream.SpanContext().TraceID())
		require.Equal(t, proxy.SpanContext().SpanID(), upstream.Parent().SpanID())

		require.Equal(t,
			"00-"+upstream.SpanContext().TraceID().String()+"-"+
				upstream.SpanContext().SpanID().String()+"-01",
			received.Get("Traceparent"),
			"the app's spans must become children of the runtime's",
		)
		require.Empty(t, received.Get("Tracestate"))

		// Exact, so a new attribute can't export request data unnoticed.
		require.Equal(t, map[string]string{
			"http.request.method":       http.MethodGet,
			"http.response.status_code": "200",
		}, spanAttributes(proxy))
		require.Equal(t, map[string]string{
			"http.request.method":       http.MethodGet,
			"http.response.status_code": "200",
			"server.address":            appURL.Hostname(),
		}, spanAttributes(upstream))
	})

	t.Run("a request without trace context has no link", func(t *testing.T) {
		serve(setup(t, true, ready()), httptest.NewRequest(http.MethodGet, "/orders", nil))

		require.Empty(t, recorded.named(t, "proxy").Links())
	})

	t.Run("a non-standard method is not exported", func(t *testing.T) {
		serve(setup(t, true, ready()), httptest.NewRequest("BREW", "/orders", nil))

		require.Equal(
			t,
			"_OTHER",
			spanAttributes(recorded.named(t, "proxy"))["http.request.method"],
		)
		require.Equal(
			t,
			"_OTHER",
			spanAttributes(recorded.named(t, "upstream"))["http.request.method"],
		)
	})

	t.Run("runtime routes are named by route class", func(t *testing.T) {
		s := setup(t, true, ready())
		for path, name := range map[string]string{
			"/enclave/v1/info":     "enclave-info",
			"/enclave/attestation": "enclave-attestation",
		} {
			serve(s, httptest.NewRequest(http.MethodGet, path, nil))
			require.Len(t, recorded.spans, 1, path)
			require.Equal(t, name, recorded.spans[0].Name())
			require.Equal(t, trace.SpanKindServer, recorded.spans[0].SpanKind())
		}
	})

	t.Run("polled and unmatched runtime routes have no span", func(t *testing.T) {
		s := setup(t, true, ready())
		for _, r := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "/health", nil),
			httptest.NewRequest(http.MethodGet, "/enclave/unknown", nil),
			httptest.NewRequest(http.MethodOptions, "/enclave/v1/info", nil),
		} {
			serve(s, r)
			require.Empty(t, recorded.spans, r.URL.Path)
		}
	})

	t.Run("the runtime's own 503 is recorded", func(t *testing.T) {
		rr := serve(
			setup(t, true, newRuntimeState()),
			httptest.NewRequest(http.MethodGet, "/orders", nil),
		)

		require.Equal(t, http.StatusServiceUnavailable, rr.Code)
		require.Len(t, recorded.spans, 1)
		proxy := recorded.named(t, "proxy")
		require.Equal(t, codes.Error, proxy.Status().Code)
		require.Equal(t, "503", spanAttributes(proxy)["http.response.status_code"])
	})

	t.Run("the proxy's own 502 is recorded", func(t *testing.T) {
		app.Close()

		rr := serve(setup(t, true, ready()), fromCaller())

		require.Equal(t, http.StatusBadGateway, rr.Code)
		proxy := recorded.named(t, "proxy")
		require.Equal(t, codes.Error, proxy.Status().Code)
		require.Equal(t, "502", spanAttributes(proxy)["http.response.status_code"])
		upstream := recorded.named(t, "upstream")
		require.Equal(t, codes.Error, upstream.Status().Code)
		require.Equal(t, "upstream request failed", upstream.Status().Description)
		require.NotContains(t, spanAttributes(upstream), "http.response.status_code")
	})
}

func TestSignedProxiedResponse(t *testing.T) {
	var received []byte
	status := http.StatusCreated
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		out := append([]byte("echo:"), received...)
		// Like typical compression middleware.
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(out)
			_ = zw.Close()
			w.Header().Set("Content-Encoding", "gzip")
			out = buf.Bytes()
		}
		w.WriteHeader(status)
		_, _ = w.Write(out)
	}))
	defer app.Close()
	appURL, err := url.Parse(app.URL)
	require.NoError(t, err)

	rt := newRuntimeState()
	rt.NotifyReady()
	attData := &AttestationData{}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	s := SetupHttpServers(
		rt, Config{AppWebSrv: appURL}, &nsmW{}, NewTelemetry(testCfg, nil), attData, "token",
	).(*servers)

	nonce := strings.Repeat("ab", nonceNumDigits/2)
	serveURI := func(uri string, header http.Header) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, uri, strings.NewReader("amount=10"))
		maps.Copy(req.Header, header)
		rr := httptest.NewRecorder()
		s.em.ServeHTTP(rr, req)
		return rr
	}
	serve := func(nonce string) *httptest.ResponseRecorder {
		if nonce == "" {
			return serveURI("/orders?x=1", nil)
		}
		return serveURI("/orders?x=1", http.Header{signNonceHeader: {nonce}})
	}

	t.Run("fails closed without a signing key, before the app sees it", func(t *testing.T) {
		require.Equal(t, http.StatusServiceUnavailable, serve(nonce).Code)
		require.Nil(t, received)
	})

	attData.SetResponseSigningKey(key)

	t.Run("rejects a malformed nonce before the app sees it", func(t *testing.T) {
		for name, nonces := range map[string][]string{
			"not 20 bytes": {strings.Repeat("ab", nonceNumDigits/2-1)},
			"not hex":      {strings.Repeat("zz", nonceNumDigits/2)},
			"repeated":     {nonce, nonce},
		} {
			rr := serveURI("/orders", http.Header{signNonceHeader: nonces})
			require.Equal(t, http.StatusBadRequest, rr.Code, name)
		}
		require.Nil(t, received)
	})

	t.Run("signs the response when asked", func(t *testing.T) {
		rr := serve(nonce)
		require.Equal(t, http.StatusCreated, rr.Code)
		require.Equal(t, "amount=10", string(received), "the app still gets the body")
		require.Equal(t, "echo:amount=10", rr.Body.String())
		requireSigned(
			t, key, rr.Header(),
			http.MethodPost, "/orders?x=1", nonce, []byte("amount=10"), rr.Code, rr.Body.Bytes(),
		)
		require.Contains(t, rr.Header().Values("Access-Control-Expose-Headers"), signatureHeader)
		require.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	})

	// Browsers always decompress and send "/a?" or "/a" interchangeably, so the
	// signature must cover the decoded body and drop an empty query.
	t.Run("signs what a browser sees", func(t *testing.T) {
		rr := serveURI("/orders?", http.Header{
			signNonceHeader: {nonce}, "Accept-Encoding": {"gzip, br"},
		})
		require.Equal(t, http.StatusCreated, rr.Code)
		require.Empty(t, rr.Header().Get("Content-Encoding"))
		require.Equal(t, "echo:amount=10", rr.Body.String())
		requireSigned(
			t, key, rr.Header(),
			http.MethodPost, "/orders", nonce, []byte("amount=10"), rr.Code, rr.Body.Bytes(),
		)
	})

	t.Run("leaves other responses unsigned", func(t *testing.T) {
		rr := serve("")
		require.Equal(t, http.StatusCreated, rr.Code)
		require.Empty(t, rr.Header().Get(signatureHeader))
	})

	t.Run("signs an unsuccessful response like any other", func(t *testing.T) {
		status = http.StatusConflict
		defer func() { status = http.StatusCreated }()
		rr := serve(nonce)
		require.Equal(t, http.StatusConflict, rr.Code)
		require.Equal(t, "echo:amount=10", rr.Body.String())
		requireSigned(
			t, key, rr.Header(),
			http.MethodPost, "/orders?x=1", nonce, []byte("amount=10"), rr.Code, rr.Body.Bytes(),
		)
	})

	t.Run("signs the proxy's own 502 when the app is down", func(t *testing.T) {
		app.Close()
		rr := serve(nonce)
		require.Equal(t, http.StatusBadGateway, rr.Code)
		requireSigned(
			t, key, rr.Header(),
			http.MethodPost, "/orders?x=1", nonce, []byte("amount=10"), rr.Code, rr.Body.Bytes(),
		)
	})
}

func TestSignedGRPCResponse(t *testing.T) {
	const service = "/test.v1.Service/"
	message := []byte{0x0a, 0x03, 'k', 'e', 'y'}
	frame := func(compressed byte, messages ...[]byte) []byte {
		var out []byte
		for _, m := range messages {
			out = append(out, compressed)
			out = binary.BigEndian.AppendUint32(out, uint32(len(m)))
			out = append(out, m...)
		}
		return out
	}
	respond := func(header http.Header, body []byte, trailers http.Header) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/grpc")
			maps.Copy(w.Header(), header)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			maps.Copy(w.Header(), trailers)
		}
	}
	ok := http.Header{http.TrailerPrefix + "Grpc-Status": {"0"}}
	for _, tc := range []struct {
		rpc        string
		handler    http.HandlerFunc
		body       []byte
		status     string // grpc-status as received, in headers or trailers
		inTrailers bool
		signed     bool
	}{
		{
			// grpc-go's own server sends trailers it never announced.
			rpc: "Unannounced", handler: respond(nil, frame(0, message), ok),
			body: frame(0, message), status: "0", inTrailers: true, signed: true,
		},
		{
			// grpc-go's ServeHTTP announces them in a Trailer header.
			rpc: "Announced", handler: respond(
				http.Header{"Trailer": {"Grpc-Status, Grpc-Message"}},
				frame(0, message), http.Header{"Grpc-Status": {"0"}},
			),
			body: frame(0, message), status: "0", inTrailers: true, signed: true,
		},
		{
			rpc: "TrailersOnly", handler: respond(http.Header{"Grpc-Status": {"5"}}, nil, nil),
			body: []byte{}, status: "5",
		},
		{
			rpc: "Failed", handler: respond(nil, frame(0, message),
				http.Header{http.TrailerPrefix + "Grpc-Status": {"13"}}),
			body: frame(0, message), status: "13", inTrailers: true, signed: true,
		},
		{
			rpc: "Compressed", handler: respond(nil, frame(1, message), ok),
			body: frame(1, message), status: "0", inTrailers: true,
		},
		{
			rpc: "Streamed", handler: respond(nil, frame(0, message, message), ok),
			body: frame(0, message, message), status: "0", inTrailers: true,
		},
	} {
		t.Run(tc.rpc, func(t *testing.T) {
			app := httptest.NewUnstartedServer(tc.handler)
			app.Config.Protocols = new(http.Protocols)
			app.Config.Protocols.SetUnencryptedHTTP2(true)
			app.Start()
			defer app.Close()
			appURL, err := url.Parse(app.URL)
			require.NoError(t, err)

			rt := newRuntimeState()
			rt.NotifyReady()
			attData := &AttestationData{}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
			attData.SetResponseSigningKey(key)
			s := SetupHttpServers(
				rt, Config{AppWebSrv: appURL}, &nsmW{}, NewTelemetry(testCfg, nil), attData, "token",
			).(*servers)
			front := httptest.NewUnstartedServer(s.ext.Handler)
			front.EnableHTTP2 = true
			front.StartTLS()
			defer front.Close()

			nonce := strings.Repeat("cd", nonceNumDigits/2)
			req, err := http.NewRequest(
				http.MethodPost, front.URL+service+tc.rpc, bytes.NewReader(frame(0, nil)),
			)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("TE", "trailers")
			req.Header.Set(signNonceHeader, nonce)
			resp, err := front.Client().Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, 2, resp.ProtoMajor)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, tc.body, body)
			if tc.inTrailers {
				require.Equal(t, tc.status, resp.Trailer.Get("Grpc-Status"))
				require.Empty(t, resp.Header.Get("Grpc-Status"), "status sent only once")
			} else {
				require.Equal(t, tc.status, resp.Header.Get("Grpc-Status"))
			}
			if !tc.signed {
				require.Empty(t, resp.Header.Get(signatureHeader))
				return
			}
			code, err := strconv.Atoi(tc.status)
			require.NoError(t, err)
			requireSigned(
				t, key, resp.Header,
				http.MethodPost, service+tc.rpc, nonce, nil, code, message,
			)
		})
	}
}

func TestSignedRequestBodyReadError(t *testing.T) {
	attData := &AttestationData{}
	attData.SetResponseSigningKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	h := signResponses(attData, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the app must not see a signed request whose body could not be read")
	}))
	body := iotest.ErrReader(errors.New("client went away"))
	req := httptest.NewRequest(http.MethodPost, "/orders", body)
	req.Header.Set(signNonceHeader, strings.Repeat("ab", nonceNumDigits/2))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestSignedEnclaveInfo(t *testing.T) {
	attData := &AttestationData{}
	s := &servers{cfg: testCfg, rm: http.NewServeMux(), rt: newRuntimeState(), attData: attData}
	require.NoError(t, s.ConfigureEnclaveInfoHandler(&migrationControlMigrator{
		previous: &PreviousPCR0Info{},
		status:   &MigrationStatus{},
	}))
	request := func(method, nonce string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/enclave/v1/info", nil)
		if nonce != "" {
			req.Header.Set(signNonceHeader, nonce)
		}
		rr := httptest.NewRecorder()
		s.rm.ServeHTTP(rr, req)
		return rr
	}
	nonce := strings.Repeat("ef", nonceNumDigits/2)

	// A candidate has no signing key yet; plain readers still get the info.
	rr := request(http.MethodGet, "")
	require.Equal(t, http.StatusOK, rr.Code)
	rr = request(http.MethodGet, nonce)
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)

	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	attData.SetResponseSigningKey(key)
	rr = request(http.MethodGet, nonce)
	require.Equal(t, http.StatusOK, rr.Code)
	requireSigned(
		t, key, rr.Header(),
		http.MethodGet, "/enclave/v1/info", nonce, nil, rr.Code, rr.Body.Bytes(),
	)

	// GET patterns also serve HEAD, whose response reaches the client bodiless;
	// the method keeps it from passing as an empty GET.
	rr = request(http.MethodHead, nonce)
	require.Equal(t, http.StatusOK, rr.Code)
	requireSigned(
		t, key, rr.Header(), http.MethodHead, "/enclave/v1/info", nonce, nil, rr.Code, nil,
	)
}

// requireSigned checks the X-Enclave-Signature in header over status and
// response, for a request with method, target, the hex nonce, and request.
func requireSigned(
	t *testing.T, key ed25519.PrivateKey, header http.Header,
	method, target, nonce string, request []byte, status int, response []byte,
) {
	t.Helper()
	rawNonce, err := hex.DecodeString(nonce)
	require.NoError(t, err)
	sig, err := base64.StdEncoding.DecodeString(header.Get(signatureHeader))
	require.NoError(t, err)
	msg := signing.ResponseMessage(method, target, rawNonce, request, status, response)
	require.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), msg, sig))
}

func TestReportBootFailure(t *testing.T) {
	s := &servers{cfg: testCfg, rm: http.NewServeMux(), rt: newRuntimeState()}
	s.ReportBootFailure(errors.New("permission preflight: role is missing SSMParams"))

	rr := httptest.NewRecorder()
	s.rm.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/enclave/v1/info", nil))

	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	var info RuntimeInfo
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &info))
	require.Equal(t, runtimeStatusFailed, info.Status)
	require.Equal(t, "permission preflight: role is missing SSMParams", info.Error)
	require.Equal(t, Version, info.Version)
}

func TestMetricsMiddleware(t *testing.T) {
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	for _, tc := range []struct {
		public         bool
		status         int
		client, server int64
		level          string
	}{
		{true, http.StatusOK, 0, 0, "INFO"},
		{true, http.StatusNotFound, 1, 0, "DEBUG"},
		{true, http.StatusUnauthorized, 1, 0, "INFO"},
		{true, 499, 1, 0, "INFO"},
		{true, http.StatusInternalServerError, 0, 1, "WARN"},
		{true, http.StatusServiceUnavailable, 0, 1, "WARN"},
		{false, http.StatusNotFound, 1, 0, "INFO"},
		{false, http.StatusForbidden, 1, 0, "INFO"},
	} {
		t.Run(fmt.Sprintf("public=%t/%d", tc.public, tc.status), func(t *testing.T) {
			var logs bytes.Buffer
			slog.SetDefault(slog.New(
				slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}),
			))
			telemetry := NewTelemetry(testCfg, nil)
			reader := testMetrics(t, telemetry)

			app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})
			metricsMiddleware(telemetry, tc.public)(app).ServeHTTP(
				httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/.env", nil),
			)

			require.Equal(t, int64(1), counterValue(t, reader, metricHTTPRequests))
			require.Equal(t, tc.client, counterValue(t, reader, metricHTTPClientErrors))
			require.Equal(t, tc.server, counterValue(t, reader, metricHTTPServerErrors))

			var record map[string]any
			require.NoError(t, json.Unmarshal(logs.Bytes(), &record))
			require.Equal(t, "http request", record["msg"])
			require.Equal(t, tc.level, record["level"])
		})
	}
}
