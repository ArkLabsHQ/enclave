package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
	"github.com/stretchr/testify/require"
)

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
		attestationHandler(&nsmW{nsm: &fakeNSM{session: session}}, hashes).ServeHTTP(rr,
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
	t.Setenv("ENCLAVE_KMS_KEY_LOCKED", "true")

	ctx := context.Background()
	ssm := NewSSM(&fakeSSM{params: map[string]string{
		migrationPreviousPCR0Param():            "previous",
		migrationPreviousPCR0AttestationParam(): "attestation",
	}})
	signer, err := NewAttestedSigner()
	require.NoError(t, err)
	rt := newRuntimeState()
	metrics := NewMetrics()
	s := &servers{em: http.NewServeMux(), rt: rt, signer: signer, metrics: metrics}

	err = s.ConfigureEnclaveInfoHandler(ctx, NewMigrator(nil, nil, ssm, nil, nil), ssm)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	s.em.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/enclave-info", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusOK)
	}
	want, err := json.Marshal(RuntimeInfo{
		Version:                  Version,
		PreviousPCR0:             "previous",
		PreviousPCR0Attestation:  "attestation",
		AttestationPubkey:        signer.Pubkey(),
		Metrics:                  metrics.MetricsSnapshot(),
		MigrationCooldownSeconds: 120,
		MigrationPending:         false,
		UpstreamApp:              rt.UpstreamAppInfo(),
		KMSKeyLocked:             true,
	})
	require.NoError(t, err)
	require.JSONEq(t, string(want), rr.Body.String())
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
