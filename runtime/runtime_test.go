package runtime

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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
// the app runs is cleared from the environment, and the app is relaunched.
func TestSuperviseRestartsAppAtInheritedSecretCutoff(t *testing.T) {
	t.Setenv("LEGACY_KEY", "inherited")
	t.Setenv("LEGACY_TOKEN", "inherited")

	rt := newRuntimeState()
	app := &fakeAppProcess{restarts: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now := time.Now()
	restart := watchInheritCutoffs(ctx, []InheritedSecret{
		{InheritSecretMetadata: InheritSecretMetadata{
			Name: "legacy", EnvVar: "LEGACY_KEY", Cutoff: now.Add(50 * time.Millisecond),
		}},
		{InheritSecretMetadata: InheritSecretMetadata{
			Name: "token", EnvVar: "LEGACY_TOKEN", Cutoff: now.Add(time.Hour),
		}},
	}, 5*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- supervise(ctx, rt, app, restart) }()

	select {
	case <-app.restarts:
	case <-time.After(2 * time.Second):
		t.Fatal("app was not restarted at the cutoff")
	}
	require.False(t, time.Now().Before(now.Add(50*time.Millisecond)), "restarted before the cutoff")

	// The relaunched app starts from the current environment.
	_, set := os.LookupEnv("LEGACY_KEY")
	require.False(t, set, "the expired secret must be gone before the app comes back")
	require.Equal(t, "inherited", os.Getenv("LEGACY_TOKEN"))

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
