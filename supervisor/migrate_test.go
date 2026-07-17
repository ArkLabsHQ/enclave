package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type migrationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f migrationRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
				strings.NewReader(`{"finalize":true,"eif_bucket":"bucket","eif_key":"image.eif","pcr0":"pcr0","secret_names":["secret"]}`),
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
	const common = `"eif_bucket":"bucket","eif_key":"image.eif","pcr0":"pcr0","secret_names":["secret"]`
	for _, tc := range []struct {
		name         string
		body         string
		wantOK       bool
		wantFinalize bool
	}{
		{name: "omitted", body: `{` + common + `}`},
		{name: "true", body: `{"finalize":true,` + common + `}`, wantOK: true, wantFinalize: true},
		{name: "false", body: `{"finalize":false,` + common + `}`, wantOK: true},
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
		})
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
