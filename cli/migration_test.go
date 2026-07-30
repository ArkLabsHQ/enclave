package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMigrationCommandRegistration(t *testing.T) {
	root := rootCmd()
	for _, path := range [][]string{
		{"migration"},
		{"migration", "request"},
		{"migration", "status"},
		{"migration", "abort"},
		{"migration", "finalise"},
	} {
		command, args, err := root.Find(path)
		if err != nil || command.Name() != path[len(path)-1] || len(args) != 0 {
			t.Errorf("command %q is not registered", strings.Join(path, " "))
		}
	}
	if command, _, err := root.Find([]string{"migration-status"}); err == nil && command.Name() == "migration-status" {
		t.Fatal("legacy migration-status command is still registered")
	}
}

func TestResolveMigrationPrecedence(t *testing.T) {
	root := t.TempDir()
	artifactPCR0 := strings.Repeat("c", 96)
	writePCRArtifact(t, root, strings.ToUpper(artifactPCR0))
	cfg := &Config{
		Region:  "config-region",
		Profile: "config-profile",
		Secrets: []SecretConfig{{Name: "secret_one"}, {Name: "secret_two"}},
	}
	outputs := TofuOutputs{
		"instance_id":               "i-tofu",
		"candidate_pcr0":            strings.Repeat("b", 96),
		"candidate_artifact_bucket": "tofu-bucket",
		"candidate_eif_key":         "tofu.eif",
		"candidate_supervisor_key":  "tofu-supervisor",
	}

	t.Run("flags override Tofu and config", func(t *testing.T) {
		opts := migrationOptions{
			region:         "flag-region",
			profile:        "flag-profile",
			instanceID:     "i-flag",
			targetPCR0:     strings.ToUpper(strings.Repeat("a", 96)),
			artifactBucket: "flag-artifact-bucket",
			eifKey:         "flag.eif",
			supervisorKey:  "flag-supervisor",
		}
		got, err := resolveMigrationValues(root, cfg, outputs, opts, "finalise")
		if err != nil {
			t.Fatal(err)
		}
		if got.region != "flag-region" || got.profile != "flag-profile" || got.instanceID != "i-flag" {
			t.Fatalf("flag resolution failed: %+v", got)
		}
		if got.targetPCR0 != strings.Repeat("a", 96) {
			t.Fatalf("target PCR0 = %q", got.targetPCR0)
		}
		if got.artifactBucket != "flag-artifact-bucket" || got.eifKey != "flag.eif" || got.supervisorKey != "flag-supervisor" {
			t.Fatalf("artifact flag resolution failed: %+v", got)
		}
	})

	t.Run("Tofu overrides artifact and config supplies AWS values", func(t *testing.T) {
		got, err := resolveMigrationValues(root, cfg, outputs, migrationOptions{}, "finalise")
		if err != nil {
			t.Fatal(err)
		}
		if got.region != "config-region" || got.profile != "config-profile" || got.instanceID != "i-tofu" {
			t.Fatalf("Tofu/config resolution failed: %+v", got)
		}
		if got.targetPCR0 != strings.Repeat("b", 96) || got.artifactBucket != "tofu-bucket" ||
			got.eifKey != "tofu.eif" || got.supervisorKey != "tofu-supervisor" {
			t.Fatalf("Tofu artifact resolution failed: %+v", got)
		}
		if strings.Join(got.secretNames, ",") != "secret_one,secret_two" {
			t.Fatalf("secret names = %v", got.secretNames)
		}
	})

	t.Run("project PCR artifact is the final PCR0 fallback", func(t *testing.T) {
		withoutPCR0 := maps.Clone(outputs)
		delete(withoutPCR0, "candidate_pcr0")
		got, err := resolveMigrationValues(root, cfg, withoutPCR0, migrationOptions{}, "finalise")
		if err != nil {
			t.Fatal(err)
		}
		if got.targetPCR0 != artifactPCR0 {
			t.Fatalf("target PCR0 = %q, want artifact %q", got.targetPCR0, artifactPCR0)
		}
	})
}

func TestNormalizePCR0(t *testing.T) {
	upper := strings.Repeat("AB", 48)
	got, err := normalizePCR0(" \n" + upper + "\t")
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ToLower(upper) {
		t.Fatalf("normalized PCR0 = %q", got)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 95), strings.Repeat("a", 97), strings.Repeat("g", 96)} {
		if _, err := normalizePCR0(invalid); err == nil {
			t.Errorf("normalizePCR0(%q) succeeded", invalid)
		}
	}
}

func TestMigrationDirectPhases(t *testing.T) {
	for _, test := range []struct {
		name           string
		args           []string
		path           string
		response       string
		wantFinalize   *bool
		wantTargetOnly bool
		wantBodyEmpty  bool
		wantOutput     []string
	}{
		{
			name:           "request",
			args:           []string{"request"},
			path:           "/migrate/request",
			response:       `{"state":"cooling_down","target_pcr0":"` + strings.Repeat("a", 96) + `","sequence":1,"action":"requested","remaining_seconds":60}`,
			wantTargetOnly: true,
			wantOutput:     []string{"config-region", strings.Repeat("a", 96)},
		},
		{
			name:          "abort",
			args:          []string{"abort"},
			path:          "/migrate/abort",
			response:      `{"state":"aborted","target_pcr0":"` + strings.Repeat("a", 96) + `","sequence":2,"action":"aborted"}`,
			wantBodyEmpty: true,
			wantOutput:    []string{"config-region"},
		},
		{
			name:         "finalise",
			args:         []string{"finalise"},
			path:         "/migrate",
			response:     migrationCompleteStream,
			wantFinalize: boolPointer(true),
			wantOutput: []string{
				"config-region",
				strings.Repeat("a", 96),
				"s3://eif-bucket/candidate.eif",
				"s3://eif-bucket/candidate-supervisor",
				"Enclave finalisation:   true",
			},
		},
		{
			name:         "resume",
			args:         []string{"finalise", "--resume"},
			path:         "/migrate",
			response:     migrationCompleteStream,
			wantFinalize: boolPointer(false),
			wantOutput: []string{
				"config-region",
				strings.Repeat("a", 96),
				"s3://eif-bucket/candidate.eif",
				"s3://eif-bucket/candidate-supervisor",
				"Enclave finalisation:   false",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := writeMigrationProject(t)
			t.Chdir(project)
			var output bytes.Buffer
			var calls int
			var gotMethod, gotPath, gotBody, outputAtMutation string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				gotMethod, gotPath = r.Method, r.URL.Path
				data, _ := io.ReadAll(r.Body)
				gotBody = string(data)
				outputAtMutation = output.String()
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.response)
			}))
			defer server.Close()

			args := append([]string{}, test.args...)
			args = append(args, mutationFlags(server.URL, test.args[0])...)
			err := executeMigrationCommand(&output, args...)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || gotMethod != http.MethodPost || gotPath != test.path {
				t.Fatalf("calls=%d method=%s path=%s", calls, gotMethod, gotPath)
			}
			for _, value := range test.wantOutput {
				if !strings.Contains(outputAtMutation, value) {
					t.Errorf("resolved output was not printed before mutation; missing %q in %q", value, outputAtMutation)
				}
			}
			if test.wantBodyEmpty && gotBody != "" {
				t.Fatalf("body = %q, want empty", gotBody)
			}
			if test.wantTargetOnly {
				var payload map[string]any
				if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
					t.Fatal(err)
				}
				if len(payload) != 1 || payload["target_pcr0"] != strings.Repeat("a", 96) {
					t.Fatalf("request payload = %#v", payload)
				}
			}
			if test.wantFinalize != nil {
				var payload struct {
					Finalize               bool     `json:"finalize"`
					EIFBucket              string   `json:"eif_bucket"`
					EIFKey                 string   `json:"eif_key"`
					PCR0                   string   `json:"pcr0"`
					SecretNames            []string `json:"secret_names"`
					SupervisorBinaryBucket string   `json:"supervisor_binary_bucket"`
					SupervisorBinaryKey    string   `json:"supervisor_binary_key"`
				}
				if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
					t.Fatal(err)
				}
				if payload.Finalize != *test.wantFinalize || payload.EIFBucket != "eif-bucket" || payload.EIFKey != "candidate.eif" ||
					payload.PCR0 != strings.Repeat("a", 96) || strings.Join(payload.SecretNames, ",") != "signing_key,api_token" ||
					payload.SupervisorBinaryBucket != "eif-bucket" || payload.SupervisorBinaryKey != "candidate-supervisor" {
					t.Fatalf("finalise payload = %+v", payload)
				}
			}
		})
	}
}

func TestMigrationStatusDirect(t *testing.T) {
	project := writeMigrationProject(t)
	t.Chdir(project)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/enclave-info" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"migration":{"state":"eligible","source_pcr0":"source","target_pcr0":"target","sequence":3,"action":"requested","published_at":"2026-01-01T00:00:00Z","eligible_at":"2026-01-01T00:01:00Z","remaining_seconds":0}}`)
	}))
	defer server.Close()

	var output bytes.Buffer
	err := executeMigrationCommand(&output, "status", "--enclave-url", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("status calls = %d, want 1", calls)
	}
	for _, field := range []string{"State:              eligible", "Source PCR0:        source", "Target PCR0:        target", "Sequence:           3", "Action:             requested", "Published at:", "Eligible at:", "Remaining seconds:  0"} {
		if !strings.Contains(output.String(), field) {
			t.Errorf("status output missing %q in %q", field, output.String())
		}
	}
}

func TestMigrationProtocolErrorsDirect(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		status int
		body   string
	}{
		{name: "request conflict", args: []string{"request"}, status: http.StatusConflict, body: "request already exists"},
		{name: "finalise too early", args: []string{"finalise"}, status: http.StatusTooEarly, body: "migration cooldown: active"},
		{name: "status unavailable", args: []string{"status"}, status: http.StatusServiceUnavailable, body: "intent store unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			project := writeMigrationProject(t)
			t.Chdir(project)
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()

			args := append([]string{}, test.args...)
			if test.args[0] == "status" {
				args = append(args, "--enclave-url", server.URL)
			} else {
				args = append(args, mutationFlags(server.URL, test.args[0])...)
			}
			var output bytes.Buffer
			err := executeMigrationCommand(&output, args...)
			if err == nil {
				t.Fatal("expected protocol error")
			}
			if !strings.Contains(err.Error(), strconv.Itoa(test.status)) || !strings.Contains(err.Error(), test.body) {
				t.Fatalf("error = %q, want status %d and body %q", err, test.status, test.body)
			}
			if calls != 1 {
				t.Fatalf("protocol calls = %d, want 1", calls)
			}
		})
	}
}

func TestSSMMigrationTransport(t *testing.T) {
	body := []byte(`{"target_pcr0":"candidate"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/migrate/request" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("body = %q, want %q", got, body)
		}
		_, _ = io.WriteString(w, `{"state":"eligible"}`)
	}))
	defer server.Close()

	fake := &fakeSessionStarter{port: portOf(t, server)}
	transport := &ssmMigrationTransport{aws: &awsClients{region: "us-east-1", sessions: fake}, instanceID: "i-remote"}
	resp, err := transport.Do(context.Background(), http.MethodPost, "/migrate/request", body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != `{"state":"eligible"}` || fake.remotePort != supervisorRemotePort || fake.cleanups != 1 {
		t.Fatalf("status=%d body=%q remote_port=%q cleanups=%d", resp.StatusCode, got, fake.remotePort, fake.cleanups)
	}

	statusServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enclave-info" {
			t.Errorf("status path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"migration":{"state":"none"}}`)
	}))
	defer statusServer.Close()
	statusFake := &fakeSessionStarter{port: portOf(t, statusServer)}
	transport.aws.sessions = statusFake
	resp, err = transport.Do(context.Background(), http.MethodGet, "/v1/enclave-info", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if statusFake.remotePort != "443" || statusFake.cleanups != 1 {
		t.Fatalf("remote_port=%q cleanups=%d", statusFake.remotePort, statusFake.cleanups)
	}
}

func TestDirectMigrationTransportContextTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&directMigrationTransport{baseURL: "http://127.0.0.1"}).Do(ctx, http.MethodGet, "/v1/enclave-info", nil)
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

func TestConsumeMigrationEvents(t *testing.T) {
	for _, test := range []struct {
		name    string
		stream  string
		wantErr string
	}{
		{name: "complete", stream: migrationCompleteStream},
		{name: "terminal error", stream: `{"step":1,"total":7,"status":"error","message":"failed"}` + "\n", wantErr: "migration failed: failed"},
		{name: "rollback", stream: `{"step":5,"total":7,"status":"rollback","message":"restoring"}` + "\n" + `{"step":5,"total":7,"status":"rollback-complete","message":"restored"}` + "\n", wantErr: "migration failed: restoring"},
		{name: "malformed", stream: `{"step":1,"total":7,"status":`, wantErr: "malformed migration event"},
		{name: "truncated", stream: `{"step":1,"total":7,"status":"progress","message":"started"}` + "\n", wantErr: "ended without completion"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := consumeMigrationEvents(strings.NewReader(test.stream), &output)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), "complete: done") {
					t.Fatalf("output = %q", output.String())
				}
				return
			}
			requireErrContains(t, err, test.wantErr)
		})
	}
}

const migrationCompleteStream = "{\"step\":1,\"total\":7,\"status\":\"progress\",\"message\":\"started\"}\n" +
	"{\"step\":7,\"total\":7,\"status\":\"complete\",\"message\":\"done\"}\n"

func executeMigrationCommand(output io.Writer, args ...string) error {
	cmd := migrationCmd()
	cmd.SetArgs(args)
	cmd.SetOut(output)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd.Execute()
}

func mutationFlags(supervisorURL, operation string) []string {
	flags := []string{"--supervisor-url", supervisorURL}
	if operation != "abort" {
		flags = append(flags, "--target-pcr0", strings.ToUpper(strings.Repeat("a", 96)))
	}
	if operation == "finalise" {
		flags = append(flags,
			"--artifact-bucket", "eif-bucket",
			"--eif-key", "candidate.eif",
			"--supervisor-key", "candidate-supervisor",
		)
	}
	return flags
}

func writeMigrationProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "enclave"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := `name: migration-test
region: config-region
profile: config-profile
secrets:
  - name: signing_key
    env_var: SIGNING_KEY
  - name: api_token
    env_var: API_TOKEN
`
	if err := os.WriteFile(filepath.Join(root, "enclave", "enclave.yaml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func writePCRArtifact(t *testing.T, root, pcr0 string) {
	t.Helper()
	dir := filepath.Join(root, ".enclave", "artifacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"PCR0": pcr0})
	if err := os.WriteFile(filepath.Join(dir, "pcr.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func boolPointer(value bool) *bool { return &value }
