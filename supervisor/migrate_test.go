package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type migrationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f migrationRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type fakeMigrationLifecycle struct {
	startContextErr error
	starts          int
	stops           int
}

func (f *fakeMigrationLifecycle) Start(ctx context.Context, _ string) error {
	f.starts++
	f.startContextErr = ctx.Err()
	return nil
}

func (f *fakeMigrationLifecycle) Stop(context.Context, string) error {
	f.stops++
	return nil
}

func TestMigrationWriteTimeoutExceedsControlAndReadiness(t *testing.T) {
	t.Setenv("ENCLAVE_MIGRATION_COMMIT_TIMEOUT", "8m")
	minimum := migrationControlTimeout + 8*time.Minute
	if got := migrationWriteTimeout(); got <= minimum {
		t.Fatalf("migration write timeout = %s, must exceed control + readiness = %s", got, minimum)
	}
}

func TestCallFinaliseMigrationUsesControlChannel(t *testing.T) {
	targetPCR0 := strings.Repeat("ab", 48)
	calls := 0
	migration := &Migration{controlClient: &http.Client{Transport: migrationRoundTripFunc(
		func(req *http.Request) (*http.Response, error) {
			calls++
			if req.Method != http.MethodPost {
				t.Fatalf("method: got %s, want POST", req.Method)
			}
			if req.URL.String() != migrationFinalisationURL {
				t.Fatalf("URL: got %s, want %s", req.URL, migrationFinalisationURL)
			}
			if req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("content type: got %q", req.Header.Get("Content-Type"))
			}
			var body struct {
				NewPCR0 string `json:"new_pcr0"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if body.NewPCR0 != targetPCR0 {
				t.Fatalf("new_pcr0: got %q, want %q", body.NewPCR0, targetPCR0)
			}
			return migrationHTTPResponse(http.StatusOK, `{}`), nil
		},
	)}}

	response, err := migration.callFinaliseMigration(context.Background(), targetPCR0)
	if err != nil {
		t.Fatalf("finalise migration: %v", err)
	}
	if response.statusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", response.statusCode)
	}
	if calls != 1 {
		t.Fatalf("calls: got %d, want 1", calls)
	}
}

func TestHandleMigrateReturnsFinaliseErrorsBeforeStreaming(t *testing.T) {
	for _, tc := range []struct {
		name       string
		transport  migrationRoundTripFunc
		wantStatus int
		wantBody   string
	}{
		{
			name: "dial failure",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("connection refused")
			},
			wantStatus: http.StatusBadGateway,
			wantBody:   "connection refused",
		},
		{
			name: "cooldown active",
			transport: func(*http.Request) (*http.Response, error) {
				return migrationHTTPResponse(http.StatusTooEarly, "migration cooldown: active"), nil
			},
			wantStatus: http.StatusTooEarly,
			wantBody:   "migration cooldown: active",
		},
		{
			name: "missing endpoint",
			transport: func(*http.Request) (*http.Response, error) {
				return migrationHTTPResponse(http.StatusNotFound, "not found"), nil
			},
			wantStatus: http.StatusNotFound,
			wantBody:   "not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			migration := &Migration{controlClient: &http.Client{Transport: tc.transport}}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(
				http.MethodPost,
				"/migrate",
				strings.NewReader(`{"finalize":true,"eif_bucket":"bucket","eif_key":"image.eif","pcr0":"`+strings.Repeat("ab", 48)+`","secret_names":["secret"]}`),
			)
			migration.handleMigrate(recorder, request)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d; body: %s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.wantBody) {
				t.Fatalf("body: got %q, want it to contain %q", recorder.Body.String(), tc.wantBody)
			}
			if recorder.Header().Get("Content-Type") == "application/x-ndjson" {
				t.Fatal("finalise failure started migration stream")
			}
		})
	}
}

func TestMigrationIntentHandlersProxyControlChannel(t *testing.T) {
	targetPCR0 := strings.Repeat("ab", 48)
	for _, tc := range []struct {
		name       string
		hostPath   string
		body       string
		wantAction string
		wantTarget string
	}{
		{
			name:       "request",
			hostPath:   "/migrate/request",
			body:       `{"target_pcr0":"` + targetPCR0 + `"}`,
			wantAction: "requested",
			wantTarget: targetPCR0,
		},
		{
			name:       "abort",
			hostPath:   "/migrate/abort",
			wantAction: "aborted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			migration := &Migration{controlClient: &http.Client{Transport: migrationRoundTripFunc(
				func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Method != http.MethodPost {
						t.Fatalf("method: got %s, want POST", req.Method)
					}
					if req.URL.String() != migrationRequestURL {
						t.Fatalf("URL: got %s, want %s", req.URL, migrationRequestURL)
					}
					var body migrationControlRequest
					if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
						t.Fatalf("decode request: %v", err)
					}
					if body.Action != tc.wantAction || body.TargetPCR0 != tc.wantTarget {
						t.Fatalf("body: got %+v, want action=%q target=%q", body, tc.wantAction, tc.wantTarget)
					}
					return migrationHTTPResponse(http.StatusOK, `{"state":"eligible"}`), nil
				},
			)}}

			mux := http.NewServeMux()
			migration.RegisterRoutes(mux)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tc.hostPath, strings.NewReader(tc.body))
			mux.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200; body: %s", recorder.Code, recorder.Body.String())
			}
			if recorder.Body.String() != `{"state":"eligible"}` {
				t.Fatalf("body: got %q", recorder.Body.String())
			}
			if calls != 1 {
				t.Fatalf("calls: got %d, want 1", calls)
			}
		})
	}
}

func TestMigrationIntentHandlerPreservesProtocolStatus(t *testing.T) {
	migration := &Migration{controlClient: &http.Client{Transport: migrationRoundTripFunc(
		func(*http.Request) (*http.Response, error) {
			return migrationHTTPResponse(http.StatusServiceUnavailable, "intent store unavailable"), nil
		},
	)}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/migrate/abort", nil)
	migration.handleMigrateAbort(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503", recorder.Code)
	}
	if recorder.Body.String() != "intent store unavailable" {
		t.Fatalf("body: got %q", recorder.Body.String())
	}
}

func TestMigrationIntentHandlersRejectDuringMigration(t *testing.T) {
	calls := 0
	migration := &Migration{controlClient: &http.Client{Transport: migrationRoundTripFunc(
		func(*http.Request) (*http.Response, error) {
			calls++
			return migrationHTTPResponse(http.StatusOK, `{}`), nil
		},
	)}}
	migration.migrateMu.Lock()
	defer migration.migrateMu.Unlock()

	mux := http.NewServeMux()
	migration.RegisterRoutes(mux)
	for _, tc := range []struct {
		path string
		body string
	}{
		{path: "/migrate/request", body: `{"target_pcr0":"` + strings.Repeat("ab", 48) + `"}`},
		{path: "/migrate/abort"},
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		mux.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusConflict {
			t.Fatalf("%s status: got %d, want 409", tc.path, recorder.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("control calls: got %d, want 0", calls)
	}
}

func TestDecodeMigrateRequestRequiresFinalize(t *testing.T) {
	common := `"eif_bucket":"bucket","eif_key":"image.eif","pcr0":"` + strings.Repeat("ab", 48) + `","secret_names":["secret"]`
	for _, tc := range []struct {
		name           string
		body           string
		wantOK         bool
		wantFinalize   bool
		wantSupervisor bool
	}{
		{name: "omitted", body: `{` + common + `}`},
		{name: "true", body: `{"finalize":true,` + common + `}`, wantOK: true, wantFinalize: true},
		{name: "false", body: `{"finalize":false,` + common + `}`, wantOK: true},
		{
			name:           "false with supervisor artifact",
			body:           `{"finalize":false,` + common + `,"supervisor_binary_bucket":"bucket","supervisor_binary_key":"supervisor"}`,
			wantOK:         true,
			wantSupervisor: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/migrate", strings.NewReader(tc.body))
			got, ok := decodeMigrateRequest(recorder, request)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v; body: %s", ok, tc.wantOK, recorder.Body.String())
			}
			if !ok {
				if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "finalize is required") {
					t.Fatalf("response: status=%d body=%q", recorder.Code, recorder.Body.String())
				}
				return
			}
			if got.Finalize == nil || *got.Finalize != tc.wantFinalize {
				t.Fatalf("finalize: got %v, want %v", got.Finalize, tc.wantFinalize)
			}
			if (got.SupervisorBinaryBucket != "") != tc.wantSupervisor {
				t.Fatalf("supervisor artifact present: got %v, want %v", got.SupervisorBinaryBucket != "", tc.wantSupervisor)
			}
		})
	}
}

func TestDecodeMigrateRequestNormalizesPCR0(t *testing.T) {
	pcr0 := strings.Repeat("AB", 48)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/migrate",
		strings.NewReader(`{"finalize":false,"eif_bucket":"bucket","eif_key":"image.eif","pcr0":"`+pcr0+`","secret_names":["secret"]}`),
	)

	got, ok := decodeMigrateRequest(recorder, request)
	if !ok {
		t.Fatalf("uppercase PCR0 rejected: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got.PCR0 != strings.ToLower(pcr0) {
		t.Fatalf("PCR0 = %q, want lowercase", got.PCR0)
	}
}

func TestVerifyCandidate(t *testing.T) {
	expectedPCR0 := strings.Repeat("ab", 48)
	for _, tc := range []struct {
		name       string
		healthBody string
		infoBody   string
		wantError  string
	}{
		{
			name:       "ready with expected PCR0",
			healthBody: `{"status":"ready"}`,
			infoBody:   `{"migration":{"source_pcr0":"` + expectedPCR0 + `"}}`,
		},
		{
			name:       "malformed health",
			healthBody: `{"status":`,
			wantError:  "decode GET /health",
		},
		{
			name:       "non-ready health",
			healthBody: `{"status":"initializing"}`,
			wantError:  `status is "initializing"`,
		},
		{
			name:       "missing PCR0",
			healthBody: `{"status":"ready"}`,
			infoBody:   `{"migration":{}}`,
			wantError:  `source_pcr0 is ""`,
		},
		{
			name:       "malformed PCR0",
			healthBody: `{"status":"ready"}`,
			infoBody:   `{"migration":{"source_pcr0":"abc"}}`,
			wantError:  `source_pcr0 is "abc"`,
		},
		{
			name:       "non-string PCR0",
			healthBody: `{"status":"ready"}`,
			infoBody:   `{"migration":{"source_pcr0":42}}`,
			wantError:  "decode GET /v1/enclave-info",
		},
		{
			name:       "noncanonical PCR0",
			healthBody: `{"status":"ready"}`,
			infoBody:   `{"migration":{"source_pcr0":"` + strings.ToUpper(expectedPCR0) + `"}}`,
			wantError:  "migration.source_pcr0 is",
		},
		{
			name:       "wrong PCR0",
			healthBody: `{"status":"ready"}`,
			infoBody:   `{"migration":{"source_pcr0":"` + strings.Repeat("cd", 48) + `"}}`,
			wantError:  "migration.source_pcr0 is",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: migrationRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/health":
					return migrationHTTPResponse(http.StatusOK, tc.healthBody), nil
				case "/v1/enclave-info":
					return migrationHTTPResponse(http.StatusOK, tc.infoBody), nil
				default:
					return nil, errors.New("unexpected candidate path")
				}
			})}

			err := verifyCandidate(context.Background(), client, "https://candidate.test", expectedPCR0)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("verify candidate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("verify candidate error = %v, want %q", err, tc.wantError)
			}
		})
	}
}

func TestAwaitEnclaveReadyRetriesStartupFailure(t *testing.T) {
	t.Setenv("ENCLAVE_URL", "https://candidate.test")
	expectedPCR0 := strings.Repeat("ab", 48)
	calls := 0
	client := &http.Client{Transport: migrationRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return migrationHTTPResponse(http.StatusServiceUnavailable, `{"status":"initializing"}`), nil
	})}

	err := (&Migration{}).awaitEnclaveReady(context.Background(), client, expectedPCR0, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("startup verification error = %v, want timeout", err)
	}
	if calls != 1 {
		t.Fatalf("startup attempts = %d, want 1 before retry timeout", calls)
	}
}

func TestAwaitMigrationOutcomeRollsBack(t *testing.T) {
	t.Setenv("ENCLAVE_URL", "https://candidate.test")
	dir := t.TempDir()
	eifDest := filepath.Join(dir, "enclave.eif")
	eifBackup := eifDest + ".backup"
	if err := os.WriteFile(eifDest, []byte("candidate"), 0o600); err != nil {
		t.Fatalf("write candidate EIF: %v", err)
	}
	if err := os.WriteFile(eifBackup, []byte("source"), 0o600); err != nil {
		t.Fatalf("write source EIF: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lifecycle := &fakeMigrationLifecycle{}
	migration := &Migration{lifecycle: lifecycle}
	recorder := httptest.NewRecorder()
	if migration.awaitMigrationOutcome(
		ctx,
		newMigrateEmitter(recorder),
		strings.Repeat("ab", 48),
		eifDest,
		eifBackup,
		"",
		"",
	) {
		t.Fatal("candidate verification unexpectedly succeeded")
	}

	if lifecycle.stops != 1 || lifecycle.starts != 1 {
		t.Fatalf("rollback lifecycle calls: stops=%d starts=%d, want 1 each", lifecycle.stops, lifecycle.starts)
	}
	if lifecycle.startContextErr != nil {
		t.Fatalf("rollback start inherited canceled request context: %v", lifecycle.startContextErr)
	}
	restored, err := os.ReadFile(eifDest)
	if err != nil {
		t.Fatalf("read restored EIF: %v", err)
	}
	if string(restored) != "source" {
		t.Fatalf("restored EIF = %q, want source", restored)
	}
	events := recorder.Body.String()
	if !strings.Contains(events, `"status":"error"`) || !strings.Contains(events, `"status":"rollback-complete"`) {
		t.Fatalf("migration events missing failure rollback: %s", events)
	}
	if strings.Contains(events, `"status":"complete"`) {
		t.Fatalf("failed activation falsely completed: %s", events)
	}
}

func TestCleanupHostArtifactsRemovesOnlyLocalMigrationFiles(t *testing.T) {
	dir := t.TempDir()
	tmpEIF := filepath.Join(dir, "new-enclave.eif")
	backup := filepath.Join(dir, "enclave.eif.backup")
	evidence := filepath.Join(dir, "transition-receipt.json")
	for _, path := range []string{tmpEIF + ".tmp", tmpEIF, backup, evidence} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	recorder := httptest.NewRecorder()
	migration := &Migration{} // A nil AWS client proves cleanup is local-only.
	if err := migration.cleanupHostArtifacts(newMigrateEmitter(recorder), tmpEIF, backup); err != nil {
		t.Fatalf("cleanup host artifacts: %v", err)
	}
	for _, path := range []string{tmpEIF + ".tmp", tmpEIF, backup} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("local artifact %s still exists or stat failed: %v", path, err)
		}
	}
	if _, err := os.Stat(evidence); err != nil {
		t.Fatalf("evidence artifact was removed: %v", err)
	}
}

func TestCleanupFailureEmitsError(t *testing.T) {
	dir := t.TempDir()
	tmpEIF := filepath.Join(dir, "new-enclave.eif")
	backup := filepath.Join(dir, "backup")
	if err := os.Mkdir(tmpEIF, 0o700); err != nil {
		t.Fatalf("mkdir temporary EIF path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpEIF, "content"), []byte("x"), 0o600); err != nil {
		t.Fatalf("make cleanup fail: %v", err)
	}
	if err := os.WriteFile(backup, []byte("source"), 0o600); err != nil {
		t.Fatalf("write EIF backup: %v", err)
	}

	recorder := httptest.NewRecorder()
	err := (&Migration{}).cleanupHostArtifacts(newMigrateEmitter(recorder), tmpEIF, backup)
	if err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("cleanup removed backup after an earlier failure: %v", err)
	}
	if !strings.Contains(recorder.Body.String(), `"status":"error"`) {
		t.Fatalf("cleanup response did not contain terminal error: %s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), `"status":"complete"`) {
		t.Fatalf("cleanup response falsely completed: %s", recorder.Body.String())
	}
}

func migrationHTTPResponse(status int, body string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
