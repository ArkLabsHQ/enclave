package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	notReady     bool
}

func (m *migrationControlMigrator) RunMigrationControl(context.Context)     {}
func (m *migrationControlMigrator) RunCandidateAttestation(context.Context) {}

func (m *migrationControlMigrator) PreviousPCR0Info(context.Context) (*PreviousPCR0Info, error) {
	return m.previous, m.previousErr
}

func (m *migrationControlMigrator) MigrationStatus(context.Context) (*MigrationStatus, error) {
	return m.status, m.statusErr
}

func (m *migrationControlMigrator) CandidateInfo(context.Context) (*CandidateInfo, error) {
	return m.candidate, m.candidateErr
}

func (m *migrationControlMigrator) Ready() bool { return !m.notReady }

func (m *migrationControlMigrator) Promote(PrimaryKMS, DEK, []StaticSecret) { m.notReady = false }

func TestServersStartReturnsBindErrors(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	t.Run("private", func(t *testing.T) {
		s := &servers{
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
			int: &http.Server{Addr: "127.0.0.1:0"},
			ext: &http.Server{},
			rt:  newRuntimeState(),
		}
		err := s.Start(context.Background(), Config{ExtPort: uint16(port)})
		require.ErrorContains(t, err, "public listener")
	})
}

func TestIsGRPCRequest(t *testing.T) {
	tests := []struct {
		name        string
		protoMajor  int
		contentType string
		want        bool
	}{
		{"native grpc over h2", 2, "application/grpc", true},
		{"grpc with proto subtype", 2, "application/grpc+proto", true},
		{"grpc with charset", 2, "application/grpc; charset=utf-8", true},
		{"grpc-web over h2", 2, "application/grpc-web+proto", true},
		{"grpc-web over h1", 1, "application/grpc-web", true},
		{"grpc-web-text over h1", 1, "application/grpc-web-text", true},
		{"grpc-web binary over h1", 1, "application/grpc-web+proto", true},
		{"json over h2", 2, "application/json", false},
		{"grpc-shaped CT over h1", 1, "application/grpc", false},
		{"empty CT over h2", 2, "", false},
		{"text plain over h2", 2, "text/plain", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.ProtoMajor = tc.protoMajor
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}

			if got := isGRPCRequest(r); got != tc.want {
				t.Fatalf("isGRPCRequest(proto=%d, ct=%q): got %v, want %v",
					tc.protoMajor, tc.contentType, got, tc.want)
			}
		})
	}
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
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodOptions, "/v1/enclave-info", nil))

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
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/enclave-info", nil))

		if rr.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusCreated)
		}
		assertCORSHeaders(t, rr.Header())
	})
}

func TestAttestationMiddleware(t *testing.T) {
	signer, err := NewAttestedSigner()
	require.NoError(t, err)

	t.Run("signs non grpc response", func(t *testing.T) {
		h := responseSignerMiddleware(
			signer,
		)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte("attested body"))
			}),
		)

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

		if rr.Code != http.StatusAccepted {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusAccepted)
		}
		if rr.Body.String() != "attested body" {
			t.Fatalf("body: got %q", rr.Body.String())
		}
		if rr.Header().Get("X-Attestation-Signature") == "" {
			t.Fatal("missing attestation signature")
		}
		if got := rr.Header().Get("X-Attestation-Pubkey"); got != signer.Pubkey() {
			t.Fatalf("pubkey: got %q, want %q", got, signer.Pubkey())
		}
	})

	t.Run("bypasses grpc", func(t *testing.T) {
		h := responseSignerMiddleware(
			signer,
		)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("stream"))
			}),
		)

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.ProtoMajor = 2
		req.Header.Set("Content-Type", "application/grpc")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Body.String() != "stream" {
			t.Fatalf("body: got %q", rr.Body.String())
		}
		if rr.Header().Get("X-Attestation-Signature") != "" {
			t.Fatal("grpc response was signed")
		}
	})
}

func TestAttestationHandler(t *testing.T) {
	t.Run("missing nonce", func(t *testing.T) {
		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{}}, NewAttestationHashes()).ServeHTTP(rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation", nil))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("bad nonce", func(t *testing.T) {
		rr := httptest.NewRecorder()
		attestationHandler(&nsmW{nsm: &fakeNSM{}}, NewAttestationHashes()).ServeHTTP(rr,
			httptest.NewRequest(http.MethodGet, "/enclave/attestation?nonce=not-hex", nil))

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("returns document bound to nonce and user data", func(t *testing.T) {
		doc := []byte("attestation document")
		session := &fakeNSMSession{responses: []response.Response{attestationDocumentResponse(doc)}}
		hashes := NewAttestationHashes()
		tlsHash := sha256.Sum256([]byte("tls"))
		signingHash := sha256.Sum256([]byte("signing"))
		hashes.SetTLSKeyHash(tlsHash)
		hashes.SetSigningKeyHash(signingHash)
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
	})
}

func TestConfigureEnclaveInfoHandler(t *testing.T) {
	t.Setenv("ENCLAVE_DEPLOYMENT", "prod")
	t.Setenv("ENCLAVE_APP_NAME", "myapp")
	t.Setenv("ENCLAVE_MIGRATION_COOLDOWN", "2m")
	t.Setenv("ENCLAVE_MIGRATION_INTENT_RETENTION", "87600h")
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")

	ctx := context.Background()
	ownPCR0 := strings.Repeat("ab", 48)
	ssm := NewSSM(&fakeSSM{params: map[string]string{
		migrationPreviousPCR0Param(ownPCR0):            "previous",
		migrationPreviousPCR0AttestationParam(ownPCR0): "attestation",
	}})
	signer, err := NewAttestedSigner()
	require.NoError(t, err)
	rt := newRuntimeState()
	metrics := NewMetrics()
	s := &servers{em: http.NewServeMux(), rt: rt, signer: signer, metrics: metrics}
	nsm := &nsmW{nsm: &fakeNSM{session: newStatefulNSMSession(t, map[uint][]byte{
		0: bytes.Repeat([]byte{0xab}, 48),
	})}}
	migrator, err := NewMigrator(nsm, ssm, newFakeS3(), migrationIntentTestBucket)
	require.NoError(t, err)

	err = s.ConfigureEnclaveInfoHandler(ctx, migrator, ssm)
	require.NoError(t, err)

	serve := func(t *testing.T) string {
		t.Helper()
		rr := httptest.NewRecorder()
		s.em.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/enclave-info", nil))
		require.Equal(t, http.StatusOK, rr.Code)
		return rr.Body.String()
	}
	want := func(t *testing.T, status string) string {
		t.Helper()
		body, err := json.Marshal(RuntimeInfo{
			Version:                  Version,
			Status:                   status,
			PreviousPCR0:             "previous",
			PreviousPCR0Attestation:  "attestation",
			AttestationPubkey:        signer.Pubkey(),
			Metrics:                  metrics.MetricsSnapshot(),
			MigrationCooldownSeconds: 120,
			Migration: &MigrationStatus{
				State: migrationStateNone, SourcePCR0: strings.Repeat("ab", 48),
			},
			UpstreamApp:  rt.UpstreamAppInfo(),
			KMSKeyLocked: true,
		})
		require.NoError(t, err)
		return string(body)
	}

	// Built with nil key material, so it is still awaiting a handoff.
	require.JSONEq(t, want(t, runtimeStatusCandidate), serve(t))

	// Promotion is visible on the same handler: it is registered once, before
	// state exists, and the migrator is filled in underneath it.
	migrator.Promote(&kmsW{keyID: "key"}, nil, nil)
	require.JSONEq(t, want(t, runtimeStatusReady), serve(t))
}

func TestConfigureEnclaveInfoHandlerFailsClosedOnStatusError(t *testing.T) {
	statusErr := fmt.Errorf("S3 unavailable: %w", errMigrationIntentStoreUnavailable)
	s := &servers{em: http.NewServeMux()}
	migrator := &migrationControlMigrator{statusErr: statusErr}
	require.NoError(t, s.ConfigureEnclaveInfoHandler(context.Background(), migrator, nil))

	rr := httptest.NewRecorder()
	s.em.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/enclave-info", nil))

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
