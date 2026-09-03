package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeAppProcess struct {
	stops int
	err   error
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

	err := supervise(ctx, rt, app)
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
	go func() { done <- supervise(context.Background(), rt, app) }()
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
	go func() { done <- supervise(ctx, rt, app) }()

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

func TestWaitForRuntimeStopsChildOnCauseCancel(t *testing.T) {
	rt := newRuntimeState()
	app := &fakeAppProcess{}
	want := errors.New("clock sync failed")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	done := make(chan error, 1)
	go func() { done <- waitForRuntime(ctx, rt, app) }()
	cancel(want)

	require.ErrorIs(t, waitTestResult(t, done), want)
	require.Equal(t, 1, app.stops)
}

// A reaped child must never be stopped: stopApp waits on the unbuffered
// ChildDone, which has already been delivered.
func TestWaitForRuntimeSkipsStopAfterChildExit(t *testing.T) {
	rt := newRuntimeState()
	app := &fakeAppProcess{}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)

	go rt.NotifyChildExit(nil)
	<-rt.ChildDone()

	done := make(chan error, 1)
	go func() { done <- waitForRuntime(ctx, rt, app) }()
	cancel(errors.New("halted"))

	_ = waitTestResult(t, done)
	require.Zero(t, app.stops)
}

func TestWaitForRuntimeReturnsListenerError(t *testing.T) {
	rt := newRuntimeState()
	want := errors.New("listener failed")

	done := make(chan error, 1)
	go func() { done <- waitForRuntime(context.Background(), rt, &fakeAppProcess{}) }()
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

func waitTestSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}
