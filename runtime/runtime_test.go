package runtime

import (
	"context"
	"errors"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAppEnv(t *testing.T) {
	for _, tc := range []struct {
		name      string
		parent    map[string]string
		allowlist string
		overrides map[string]string
		secrets   []StaticSecret
		want      map[string]string
	}{
		{
			name:   "missing SSM override preserves baked values",
			parent: map[string]string{"CHILD_ENV_TEST_SETTING": "baked"},
			want:   map[string]string{"CHILD_ENV_TEST_SETTING": "baked"},
		},
		{
			name:      "SSM overrides baked values",
			parent:    map[string]string{"CHILD_ENV_TEST_SETTING": "baked"},
			allowlist: "CHILD_ENV_TEST_SETTING",
			overrides: map[string]string{"CHILD_ENV_TEST_SETTING": "ssm"},
			want:      map[string]string{"CHILD_ENV_TEST_SETTING": "ssm"},
		},
		{
			name:      "secrets override SSM and baked values",
			parent:    map[string]string{"CHILD_ENV_TEST_KEY": "baked"},
			allowlist: "CHILD_ENV_TEST_KEY,CHILD_ENV_TEST_SETTING",
			overrides: map[string]string{
				"CHILD_ENV_TEST_KEY": "host-value", "CHILD_ENV_TEST_SETTING": "keep",
			},
			secrets: []StaticSecret{
				{StaticSecretMetadata: StaticSecretMetadata{EnvVar: "CHILD_ENV_TEST_KEY"}, Plaintext: "secret"},
			},
			want: map[string]string{
				"CHILD_ENV_TEST_KEY": "secret", "CHILD_ENV_TEST_SETTING": "keep",
			},
		},
		{
			name: "runtime ports and token override every other source",
			parent: map[string]string{
				envAppPort: "1111", "PORT": "1111",
				"ENCLAVE_PROXY_PORT": "1112", "ENCLAVE_RUNTIME_TOKEN": "baked-token",
			},
			allowlist: "PORT,ENCLAVE_PROXY_PORT,ENCLAVE_RUNTIME_TOKEN",
			overrides: map[string]string{
				"PORT": "2222", "ENCLAVE_PROXY_PORT": "2223", "ENCLAVE_RUNTIME_TOKEN": "host-token",
			},
			secrets: []StaticSecret{
				{StaticSecretMetadata: StaticSecretMetadata{EnvVar: envAppPort}, Plaintext: "3333"},
				{StaticSecretMetadata: StaticSecretMetadata{EnvVar: "PORT"}, Plaintext: "3333"},
				{StaticSecretMetadata: StaticSecretMetadata{EnvVar: "ENCLAVE_PROXY_PORT"}, Plaintext: "3334"},
				{StaticSecretMetadata: StaticSecretMetadata{EnvVar: "ENCLAVE_RUNTIME_TOKEN"}, Plaintext: "secret-token"},
			},
		},
		{
			name:      "SSM app port reaches both child port variables",
			overrides: map[string]string{envAppPort: "9090"},
			want:      map[string]string{envAppPort: "9090", "PORT": "9090"},
		},
		{
			name:      "explicitly empty SSM override clears baked value",
			parent:    map[string]string{"CHILD_ENV_TEST_SETTING": "baked"},
			allowlist: "CHILD_ENV_TEST_SETTING",
			overrides: map[string]string{"CHILD_ENV_TEST_SETTING": ""},
			want:      map[string]string{"CHILD_ENV_TEST_SETTING": ""},
		},
		{
			name:      "values survive serialization unchanged",
			allowlist: "CHILD_ENV_TEST_SETTING",
			overrides: map[string]string{"CHILD_ENV_TEST_SETTING": "  café\nkey=value \t"},
			want:      map[string]string{"CHILD_ENV_TEST_SETTING": "  café\nkey=value \t"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setConfigTestEnv(t, false)
			t.Setenv(envOverrideAllowList, tc.allowlist)
			cfg, err := LoadConfig()
			require.NoError(t, err)
			for key, value := range tc.parent {
				t.Setenv(key, value)
			}
			parentEnv := os.Environ()

			params := make(map[string]string)
			for key, value := range tc.overrides {
				params["/prod/app/env/"+key] = value
			}
			require.NoError(t, cfg.ApplySSMOverlay(t.Context(), NewSSM(&fakeSSM{params: params})))
			overrides := maps.Clone(cfg.ChildEnv)

			entries := (&exec.Cmd{
				Env: appEnv(*cfg, "runtime-token", Secrets{Static: tc.secrets}),
			}).Environ()
			values := make(map[string]string)
			counts := make(map[string]int)
			for _, entry := range entries {
				key, value, _ := strings.Cut(entry, "=")
				values[key] = value
				counts[key]++
			}
			want := map[string]string{
				envAppPort: "7074", "PORT": "7074",
				"ENCLAVE_PROXY_PORT": "8080", "ENCLAVE_RUNTIME_TOKEN": "runtime-token",
			}
			maps.Copy(want, tc.want)
			for key, value := range want {
				require.Equal(
					t,
					1,
					counts[key],
					"%s must appear exactly once, even when empty",
					key,
				)
				require.Equal(t, value, values[key], key)
			}
			require.Equal(t, "http://127.0.0.1:"+want["PORT"], cfg.AppWebSrv.String())
			require.Equal(t, overrides, cfg.ChildEnv, "appEnv must not change the config overrides")
			require.True(
				t,
				slices.Equal(parentEnv, os.Environ()),
				"parent environment must not change",
			)
		})
	}
}

type fakeAppProcess struct {
	stops    int
	restarts chan struct{}
	err      error
}

func (a *fakeAppProcess) Restart() error {
	a.restarts <- struct{}{}
	return nil
}

func (a *fakeAppProcess) Stop() error {
	a.stops++
	return a.err
}

func TestSuperviseContextDoneStopsApp(t *testing.T) {
	rt := newRuntimeState()
	want := errors.New("stop failed")
	app := &fakeAppProcess{err: want}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := supervise(ctx, rt, app, nil)
	if !errors.Is(err, want) {
		t.Fatalf("supervise error = %v, want %v", err, want)
	}
	if app.stops != 1 {
		t.Fatalf("Stop calls = %d, want 1", app.stops)
	}
}

func TestSuperviseListenerErrorStopsApp(t *testing.T) {
	rt := newRuntimeState()
	app := &fakeAppProcess{}
	want := errors.New("listener failed")

	done := make(chan error, 1)
	go func() { done <- supervise(context.Background(), rt, app, nil) }()
	rt.NotifyListenerError(want)

	err := waitTestResult(t, done)
	if !errors.Is(err, want) {
		t.Fatalf("supervise error = %v, want %v", err, want)
	}
	if app.stops != 1 {
		t.Fatalf("Stop calls = %d, want 1", app.stops)
	}
}

func TestSuperviseChildExitWaitsForRuntime(t *testing.T) {
	rt := newRuntimeState()
	app := &fakeAppProcess{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- supervise(ctx, rt, app, nil) }()

	rt.NotifyChildExit(nil)
	cancel()

	if err := waitTestResult(t, done); err != nil {
		t.Fatalf("supervise error = %v, want nil", err)
	}
	if app.stops != 0 {
		t.Fatalf("Stop calls = %d, want 0", app.stops)
	}
	if !rt.UpstreamAppInfo().Exited {
		t.Fatalf("UpstreamAppInfo().Exited = false, want true")
	}
}

// A cutoff restart relaunches the app and keeps supervising it.
func TestSuperviseRestartRelaunchesApp(t *testing.T) {
	rt := newRuntimeState()
	app := &fakeAppProcess{restarts: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	restart := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- supervise(ctx, rt, app, restart) }()

	restart <- struct{}{}
	select {
	case <-app.restarts:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for restart")
	}
	cancel()

	require.NoError(t, waitTestResult(t, done))
	require.Equal(t, 1, app.stops)
}

// The whole cutoff path short of the exec: a secret reaching its cutoff while
// the app runs is left out of its environment, and the app is relaunched.
func TestSuperviseRestartsAppAtInheritedSecretCutoff(t *testing.T) {
	rt := newRuntimeState()
	app := &fakeAppProcess{restarts: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now()
	legacy := InheritSecretMetadata{
		Name: "legacy", EnvVar: "LEGACY_KEY", Cutoff: now.Add(50 * time.Millisecond),
	}
	token := InheritSecretMetadata{
		Name: "token", EnvVar: "LEGACY_TOKEN", Cutoff: now.Add(time.Hour),
	}
	// Without a cutoff, a secret is neither watched nor ever dropped.
	forever := InheritSecretMetadata{Name: "forever", EnvVar: "LEGACY_FOREVER"}
	secrets := Secrets{
		Inherited: []InheritedSecret{
			{InheritSecretMetadata: legacy, Plaintext: "inherited"},
			{InheritSecretMetadata: token, Plaintext: "inherited"},
			{InheritSecretMetadata: forever, Plaintext: "inherited"},
		},
		metadata: SecretsMetadata{Inherited: []InheritSecretMetadata{legacy, token, forever}},
	}
	restart := watchInheritCutoffs(ctx, secrets.Inherited, 5*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- supervise(ctx, rt, app, restart) }()

	select {
	case <-app.restarts:
	case <-time.After(2 * time.Second):
		t.Fatal("app was not restarted at the cutoff")
	}
	require.False(t, time.Now().Before(now.Add(50*time.Millisecond)), "restarted before the cutoff")

	// The relaunched app's environment is built at relaunch.
	relaunched := secrets.applyTo(nil, time.Now())
	require.Equal(t, []string{"LEGACY_TOKEN=inherited", "LEGACY_FOREVER=inherited"}, relaunched,
		"the expired secret must be gone before the app comes back")

	select {
	case <-app.restarts:
		t.Fatal("app restarted again with no further cutoff due")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	require.NoError(t, waitTestResult(t, done))
	require.Equal(t, 1, app.stops)
}

func TestNotifyChildStartClearsExit(t *testing.T) {
	rt := newRuntimeState()
	go func() { <-rt.ChildDone() }()
	rt.NotifyChildExit(errors.New("killed"))
	require.True(t, rt.UpstreamAppInfo().Exited)

	rt.NotifyChildStart()
	require.Equal(t, UpstreamAppInfo{}, rt.UpstreamAppInfo())
}

func TestWaitForRuntimeReturnsCancelCause(t *testing.T) {
	rt := newRuntimeState()
	want := errors.New("clock sync failed")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	done := make(chan error, 1)
	go func() { done <- waitForRuntime(ctx, rt) }()
	cancel(want)

	require.ErrorIs(t, waitTestResult(t, done), want)
}

func TestWaitForRuntimeReturnsListenerError(t *testing.T) {
	rt := newRuntimeState()
	want := errors.New("listener failed")

	done := make(chan error, 1)
	go func() { done <- waitForRuntime(context.Background(), rt) }()
	rt.NotifyListenerError(want)

	err := waitTestResult(t, done)
	if !errors.Is(err, want) {
		t.Fatalf("waitForRuntime error = %v, want %v", err, want)
	}
}

func waitTestResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for result")
		return nil
	}
}

func TestRuntimeStateLifecycleOnlyMovesForward(t *testing.T) {
	rt := newRuntimeState()
	require.Equal(t, runtimeStatusCandidate, rt.Status())
	require.False(t, rt.Ready())

	rt.NotifyStarting()
	require.Equal(t, runtimeStatusStarting, rt.Status())
	require.False(t, rt.Ready())

	rt.NotifyReady()
	require.Equal(t, runtimeStatusReady, rt.Status())
	require.True(t, rt.Ready())

	// Ready is terminal.
	rt.NotifyStarting()
	require.Equal(t, runtimeStatusReady, rt.Status())
}
