package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeAppProcess struct {
	stops int
	err   error
}

func (a *fakeAppProcess) Stop() error {
	a.stops++
	return a.err
}

type observableRuntimeState struct {
	*runtimeState
	listenCalls chan struct{}
}

func (r *observableRuntimeState) ListenError() <-chan error {
	select {
	case r.listenCalls <- struct{}{}:
	default:
	}
	return r.runtimeState.ListenError()
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

func TestSuperviseHaltWaitsForRuntime(t *testing.T) {
	rt := &observableRuntimeState{
		runtimeState: newRuntimeState(),
		listenCalls:  make(chan struct{}, 2),
	}
	app := &fakeAppProcess{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt.NotifyHalt()

	done := make(chan error, 1)
	go func() { done <- supervise(ctx, rt, app) }()

	waitTestSignal(t, rt.listenCalls)
	waitTestSignal(t, rt.listenCalls)
	cancel()

	if err := waitTestResult(t, done); err != nil {
		t.Fatalf("supervise error = %v, want nil", err)
	}
	if app.stops != 0 {
		t.Fatalf("Stop calls = %d, want 0", app.stops)
	}
	if !rt.Halted() {
		t.Fatalf("Halted() = false, want true")
	}
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

func waitTestSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}
