// Package runtime boots the in-enclave supervisor: networking, servers, TLS, AWS state, and app process.
package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/codes"
)

// Runtime status moves from candidate to starting to ready.
const (
	runtimeStatusCandidate = "candidate"
	runtimeStatusStarting  = "starting"
	runtimeStatusReady     = "ready"
)

type RuntimeState interface {
	Status() string
	NotifyStarting()
	Ready() bool
	NotifyReady()
	UpstreamAppInfo() UpstreamAppInfo
	SetTLSCertCallback(cb TLSCertCallback)
	GetTLSCertCallback(ctx context.Context) (TLSCertCallback, error)
	NotifyListenerError(err error)
	ListenError() <-chan error
	NotifyChildStart()
	NotifyChildExit(err error)
	ChildDone() <-chan error
}

func Run(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	ctx, err := StartClockSyncer(ctx, &cfg)
	if err != nil {
		return fmt.Errorf("clock sync failed: %w", err)
	}

	if err := StartNetorking(ctx, cfg); err != nil {
		return fmt.Errorf("starting networking failed: %w", err)
	}

	aws, err := NewAWSClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS clients: %w", err)
	}
	ssm := NewSSM(aws.SSM)
	if err := ApplyEnvOverrides(ctx, &cfg, ssm); err != nil {
		return fmt.Errorf("failed to apply env overrides: %w", err)
	}

	cfg.InstanceID = aws.InstanceID
	telemetry := NewTelemetry(&cfg, aws.CWL)
	if err := telemetry.Start(ctx); err != nil {
		return err
	}

	defer telemetry.Shutdown()

	ctx, initSpan := telemetry.Tracing.Span(ctx, "init")
	initSpanEnded := false

	defer func() {
		if !initSpanEnded {
			initSpan.End()
		}
	}()

	hashes := &AttestationHashes{}

	authToken, err := generateRuntimeToken()
	if err != nil {
		return fmt.Errorf("generate runtime token: %w", err)
	}

	rt := newRuntimeState()

	nsm := NewNSM(WithAttestationUnsigned(cfg.InsecureVerifySkipped))

	servers := SetupHttpServers(
		rt,
		cfg,
		nsm,
		telemetry,
		hashes,
		authToken,
	)

	if err := servers.Start(ctx, cfg); err != nil {
		return fmt.Errorf("failed to start HTTP servers: %w", err)
	}

	boot, err := NewBoot(&cfg, nsm, aws.KMS, aws.STS, ssm, aws.S3)
	if err != nil {
		return fmt.Errorf("failed to establish state: %w", err)
	}

	migrationIntentBucket, err := boot.migrationIntentBucket(ctx)
	if err != nil {
		return fmt.Errorf("failed to resolve migration intent bucket: %w", err)
	}

	migrator, err := NewMigrator(
		&cfg,
		nsm,
		NewSSMTTLCache(ssm, time.Second*5),
		aws.S3,
		migrationIntentBucket,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize migrator: %w", err)
	}

	if err := servers.ConfigureEnclaveInfoHandler(migrator); err != nil {
		return fmt.Errorf("failed to configure enclave info handler: %w", err)
	}

	candidateCertCb, err := candidateCertCallback(cfg.FQDN)
	if err != nil {
		return fmt.Errorf("failed to configure candidate TLS: %w", err)
	}
	rt.SetTLSCertCallback(withDefaultSNI(cfg.FQDN, candidateCertCb))

	// Candidates wait here until their predecessor commits the handoff.
	if err := migrator.AwaitCandidateHandoff(ctx); err != nil {
		return fmt.Errorf("failed to await migration handoff: %w", err)
	}

	result, err := boot.Boot(ctx)
	if err != nil {
		return fmt.Errorf("failed to establish state: %w", err)
	}

	rt.NotifyStarting()

	if err := ExtendPCRRegistersWithStaticSecrets(nsm, result.secrets.Static); err != nil {
		return fmt.Errorf("failed to extend PCR registers with static secrets: %w", err)
	}

	servers.SetAncestry(ctx, NewAncestry(&cfg, nsm, ssm, result.kms, result.lineage))

	go migrator.RunPredecessorHandoff(
		ctx,
		result.kms,
		result.dek,
		result.secrets.Static,
		result.tlsKey,
	)

	tlsCertCb, err := ConfigureTLS(
		ctx, &cfg, aws.S3, result.dek, ssm, aws.Route53, result.tlsKey, hashes,
	)
	if err != nil {
		return fmt.Errorf("failed to configure TLS: %w", err)
	}
	rt.SetTLSCertCallback(withDefaultSNI(cfg.FQDN, tlsCertCb))

	// IMPORTANT: Set secret env vars *AFTER* SSM env override to prevent host from
	// overriding established secret state
	if err := result.secrets.SetEnvVars(); err != nil {
		return fmt.Errorf("failed to set secrets env vars: %w", err)
	}

	app, err := startApp(rt, cfg, authToken)
	if err != nil {
		return fmt.Errorf("failed to start upstream app: %w", err)
	}

	restart := watchInheritCutoffs(
		ctx,
		result.secrets.Inherited,
		inheritCutoffPollInterval,
	)

	initSpan.SetStatus(codes.Ok, "")
	initSpan.End()
	initSpanEnded = true

	return supervise(ctx, rt, app, restart)
}

type appProcess interface {
	Stop() error
	// Restart stops the app and launches it again with the current environment.
	Restart() error
}

type execApp struct {
	rt        RuntimeState
	cfg       Config
	authToken string
	cmd       *exec.Cmd
}

func startApp(rt RuntimeState, cfg Config, authToken string) (appProcess, error) {
	app := &execApp{rt: rt, cfg: cfg, authToken: authToken}
	if err := app.launch(); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *execApp) launch() error {
	rt, cfg, authToken := a.rt, a.cfg, a.authToken
	appPath := "/app/" + getAppBinaryName()

	child := exec.Command(appPath)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(
		os.Environ(),
		"ENCLAVE_APP_PORT="+cfg.AppPort,
		"PORT="+cfg.AppPort,
		"ENCLAVE_PROXY_PORT="+strconv.Itoa(int(cfg.IntPort)),
		"ENCLAVE_RUNTIME_TOKEN="+authToken,
	)

	if err := child.Start(); err != nil {
		return fmt.Errorf("start child %s: %w", appPath, err)
	}

	rt.NotifyChildStart()
	rt.NotifyReady()
	slog.Info("child started", "path", appPath, "pid", child.Process.Pid)

	go func() { rt.NotifyChildExit(child.Wait()) }()

	a.cmd = child
	return nil
}

func stopApp(rt RuntimeState, child *exec.Cmd) error {
	_ = child.Process.Signal(syscall.SIGTERM)

	select {
	case <-rt.ChildDone():
	case <-time.After(time.Second * 10):
		slog.Warn("child did not exit, sending SIGKILL")
		_ = child.Process.Kill()
		<-rt.ChildDone()
	}
	return nil
}

func (a *execApp) Stop() error {
	return stopApp(a.rt, a.cmd)
}

func (a *execApp) Restart() error {
	if err := a.Stop(); err != nil {
		return err
	}
	return a.launch()
}

// supervise runs until the runtime stops. A signal on restart relaunches the
// app, so it comes back without an inherited secret past its cutoff.
func supervise(
	ctx context.Context,
	rt RuntimeState,
	child appProcess,
	restart <-chan struct{},
) error {
	for {
		select {
		case err := <-rt.ChildDone():
			if err != nil {
				slog.Error("upstream app exited; runtime stays alive", "error", err)
			} else {
				slog.Warn("upstream app exited cleanly; runtime stays alive")
			}
			return waitForRuntime(ctx, rt)

		case <-restart:
			slog.Info("restarting upstream app without expired inherited secrets")
			if err := child.Restart(); err != nil {
				slog.Error("upstream app failed to restart; runtime stays alive", "error", err)
				return waitForRuntime(ctx, rt)
			}

		case err := <-rt.ListenError():
			_ = child.Stop()
			return fmt.Errorf("HTTP listener failed: %w", err)

		case <-ctx.Done():
			if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
				_ = child.Stop()
				return fmt.Errorf("runtime halted: %w", cause)
			}
			slog.Info("shutting down")
			return child.Stop()
		}
	}
}

// waitForRuntime keeps the runtime alive after the app has exited, so
// health and migration endpoints still answer.
func waitForRuntime(ctx context.Context, rt RuntimeState) error {
	select {
	case err := <-rt.ListenError():
		return fmt.Errorf("HTTP listener failed: %w", err)
	case <-ctx.Done():
		if cause := context.Cause(ctx); cause != nil && cause != context.Canceled {
			return fmt.Errorf("runtime halted: %w", cause)
		}
		slog.Info("shutting down")
		return nil
	}
}

type runtimeState struct {
	status          atomic.Value // one of the runtimeStatus constants
	isExit          atomic.Bool
	exitError       atomic.Value
	tlsReadyOnce    sync.Once
	tlsMu           sync.RWMutex
	tlsCertCallback TLSCertCallback
	tlsReadyCh      chan struct{}
	listenErrCh     chan error
	childDoneCh     chan error
}

func (r *runtimeState) Status() string {
	return r.status.Load().(string)
}

// NotifyStarting records that enclave state is available.
func (r *runtimeState) NotifyStarting() {
	r.status.CompareAndSwap(runtimeStatusCandidate, runtimeStatusStarting)
}

func (r *runtimeState) Ready() bool {
	return r.Status() == runtimeStatusReady
}

func (r *runtimeState) NotifyReady() {
	r.status.Store(runtimeStatusReady)
}

func (r *runtimeState) UpstreamAppInfo() UpstreamAppInfo {
	exitErr := ""
	if v := r.exitError.Load(); v != nil {
		if s, ok := v.(string); ok {
			exitErr = s
		}
	}
	return UpstreamAppInfo{
		Exited: r.isExit.Load(),
		Error:  exitErr,
	}
}

// SetTLSCertCallback replaces the certificate source. Run calls it twice: a
// throwaway certificate while the enclave is a candidate, then the real one once
// state is established. Every call swaps the callback, which each handshake reads
// afresh; only the first unblocks handshakes waiting for one, so it is not a Once.
func (r *runtimeState) SetTLSCertCallback(cb TLSCertCallback) {
	r.tlsMu.Lock()
	r.tlsCertCallback = cb
	r.tlsMu.Unlock()

	r.tlsReadyOnce.Do(func() { close(r.tlsReadyCh) })
}

func (r *runtimeState) GetTLSCertCallback(ctx context.Context) (TLSCertCallback, error) {
	select {
	case <-r.tlsReadyCh:
		r.tlsMu.RLock()
		defer r.tlsMu.RUnlock()
		return r.tlsCertCallback, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *runtimeState) NotifyListenerError(err error) {
	r.listenErrCh <- err
}

func (r *runtimeState) ListenError() <-chan error {
	return r.listenErrCh
}

// NotifyChildStart clears the exit record of a previous app process.
func (r *runtimeState) NotifyChildStart() {
	r.isExit.Store(false)
	r.exitError.Store("")
}

func (r *runtimeState) NotifyChildExit(err error) {
	r.isExit.Store(true)
	if err != nil {
		r.exitError.Store(err.Error())
	}
	r.childDoneCh <- err
}

func (r *runtimeState) ChildDone() <-chan error {
	return r.childDoneCh
}

func newRuntimeState() *runtimeState {
	r := &runtimeState{
		tlsReadyCh:  make(chan struct{}),
		listenErrCh: make(chan error, 4),
		childDoneCh: make(chan error),
	}
	r.status.Store(runtimeStatusCandidate)
	return r
}
