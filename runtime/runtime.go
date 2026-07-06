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
)

type RuntimeState interface {
	Ready() bool
	NotifyReady()
	NotifyHalt()
	Halt() <-chan struct{}
	Halted() bool
	UpstreamAppInfo() UpstreamAppInfo
	SetTLSCertCallback(cb TLSCertCallback)
	// GetTLSCertCallback blocks until TLS is ready.
	GetTLSCertCallback(ctx context.Context) (TLSCertCallback, error)
	NotifyListenerError(err error)
	ListenError() <-chan error
	NotifyChildExit(err error)
	ChildDone() <-chan error
}

func Run(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if err := StartNetorking(ctx, cfg); err != nil {
		return fmt.Errorf("starting networking failed: %w", err)
	}

	aws, err := NewAWSClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS clients: %w", err)
	}

	metrics := NewMetrics()
	tracing := NewTracing(aws.CWL)

	if err := tracing.StartCloudWatchExport(ctx); err != nil {
		return fmt.Errorf("failed to start tracing cloud watch export: %w", err)
	}

	logging := NewLogging(metrics, aws.CWL)
	slog.SetDefault(slog.New(NewBufferHandler(logging)))

	if err := logging.StartCloudWatchExport(ctx); err != nil {
		return fmt.Errorf("failed to start logging cloud watch export: %w", err)
	}

	hashes := NewAttestationHashes()

	attestationSigner, err := NewAttestationSigner()
	if err != nil {
		return fmt.Errorf("failed to create attestation signer: %w", err)
	}

	hashes.SetSigningKeyHash(attestationSigner.PubkeyHash())

	authToken, err := generateRuntimeToken()
	if err != nil {
		return fmt.Errorf("generate runtime token: %w", err)
	}

	rt := newRuntimeState()

	nsm := nsmFromEnv()

	servers := SetupHttpServers(
		rt,
		cfg,
		nsm,
		metrics,
		logging,
		tracing,
		attestationSigner,
		hashes,
		authToken,
	)

	servers.Start(ctx, cfg)

	ssm := NewSSM(aws.SSM)
	ssmWithCache := NewSSMTTLCache(ssm, time.Second*5)

	if err := VerifyPredecessorCommitment(ctx, nsm, ssm); err != nil {
		return fmt.Errorf("failed to verifier predecessor commitment: %w", err)
	}

	kms, err := FetchOrCreatePrimaryKMS(ctx, nsm, aws.KMS, aws.STS, ssmWithCache)
	if err != nil {
		return fmt.Errorf("failed to fetch/create primary KMS key: %w", err)
	}

	staticSecretMeta, err := LoadStaticSecretMetadata()
	if err != nil {
		return fmt.Errorf("failed to load static secret metadata: %w", err)
	}

	startState, err := ClassifyStartState(ctx, kms, ssmWithCache, staticSecretMeta)
	if err != nil {
		return fmt.Errorf("failed to classify start state: %w", err)
	}

	dek, err := FetchOrInitDEK(ctx, kms, ssmWithCache)
	if err != nil {
		return fmt.Errorf("failed to fetch or init DEK: %w", err)
	}

	secrets, err := FetchOrInitStaticSecrets(ctx, kms, ssmWithCache, staticSecretMeta)
	if err != nil {
		return fmt.Errorf("failed to fetch or init static secrets: %w", err)
	}

	stateOrigin, err := EstablishStateOrigin(
		ctx,
		nsm,
		kms,
		ssmWithCache,
		staticSecretMeta,
		startState,
	)
	if err != nil {
		return fmt.Errorf("failed to estabilish state origin: %w", err)
	}

	migrator := NewMigrator(nsm, kms, ssmWithCache, dek, stateOrigin, secrets)

	if err := servers.ConfigureEnclaveInfoHandler(ctx, migrator, ssm); err != nil {
		return fmt.Errorf("failed to configure enclave info handler: %w", err)
	}

	if err := servers.ConfigureMigrationHandler(ctx, migrator); err != nil {
		return fmt.Errorf("failed to configure migration handler: %w", err)
	}

	tlsCertCb, err := ConfigureTLS(ctx, &cfg, aws.S3, dek, ssm, hashes)
	if err != nil {
		return fmt.Errorf("failed to configure TLS: %w", err)
	}
	rt.SetTLSCertCallback(tlsCertCb)

	freshnessAnchor, err := NewFreshnessAnchor(ctx, rt, aws.S3, dek, ssm)
	if err != nil {
		return fmt.Errorf("failed to create freshness anchor: %w", err)
	}

	kvStore, err := NewKVStore(ctx, aws.DDB, ssm, dek, freshnessAnchor)
	if err != nil {
		return fmt.Errorf("failed to create kv store: %w", err)
	}

	if err := servers.StartRESPServer(ctx, NewRESPServer(rt, kvStore, authToken)); err != nil {
		return fmt.Errorf("failed to start RESP server: %w", err)
	}

	if err := ApplyEnvOverrides(ctx, ssm); err != nil {
		return fmt.Errorf("failed to apply env overrides: %w", err)
	}

	app, err := startApp(rt, cfg, authToken)
	if err != nil {
		return fmt.Errorf("failed to start upstream app: %w", err)
	}

	return supervise(ctx, rt, app)
}

func nsmFromEnv() NSM {
	return NewNSM(WithAttestationUnsigned(skipCOSEVerification()))
}

type appProcess interface {
	Stop() error
}

type execApp struct {
	rt  RuntimeState
	cmd *exec.Cmd
}

func startApp(rt RuntimeState, cfg Config, authToken string) (appProcess, error) {
	appPath := "/app/" + envOr("APP_BINARY_NAME", "app")
	appPort := envOr("ENCLAVE_APP_PORT", "7074")

	child := exec.Command(appPath)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = append(
		os.Environ(),
		"ENCLAVE_APP_PORT="+appPort,
		"PORT="+appPort,
		"ENCLAVE_PROXY_PORT="+strconv.Itoa(int(cfg.IntPort)),
		"ENCLAVE_RUNTIME_TOKEN="+authToken,
	)

	if err := child.Start(); err != nil {
		return nil, fmt.Errorf("start child %s: %w", appPath, err)
	}

	rt.NotifyReady()
	slog.Info("child started", "path", appPath, "pid", child.Process.Pid)

	go func() { rt.NotifyChildExit(child.Wait()) }()

	return &execApp{rt: rt, cmd: child}, nil
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

func supervise(ctx context.Context, rt RuntimeState, child appProcess) error {
	select {
	case err := <-rt.ChildDone():
		if err != nil {
			slog.Error("upstream app exited; runtime stays alive", "error", err)
		} else {
			slog.Warn("upstream app exited cleanly; runtime stays alive")
		}
		return waitForRuntime(ctx, rt)

	case err := <-rt.ListenError():
		_ = child.Stop()
		return fmt.Errorf("HTTP listener failed: %w", err)

	case <-rt.Halt():
		slog.Info("received halt circuit-breaker")
		return waitForRuntime(ctx, rt)

	case <-ctx.Done():
		slog.Info("shutting down")
		return child.Stop()
	}
}

func waitForRuntime(ctx context.Context, rt RuntimeState) error {
	select {
	case err := <-rt.ListenError():
		return fmt.Errorf("HTTP listener failed: %w", err)
	case <-ctx.Done():
		slog.Info("shutting down")
		return nil
	}
}

type runtimeState struct {
	isReady         atomic.Bool
	isExit          atomic.Bool
	exitError       atomic.Value
	rollbackHalt    atomic.Bool
	haltOnce        sync.Once
	haltCh          chan struct{}
	tlsReadyOnce    sync.Once
	tlsCertCallback TLSCertCallback
	tlsReadyCh      chan struct{}
	listenErrCh     chan error
	childDoneCh     chan error
}

func (r *runtimeState) Ready() bool {
	return r.isReady.Load()
}

func (r *runtimeState) NotifyReady() {
	r.isReady.Store(true)
}

func (r *runtimeState) NotifyHalt() {
	r.rollbackHalt.Store(true)
	r.haltOnce.Do(func() {
		close(r.haltCh)
	})
}

func (r *runtimeState) Halt() <-chan struct{} {
	return r.haltCh
}

func (r *runtimeState) Halted() bool {
	return r.rollbackHalt.Load()
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

func (r *runtimeState) SetTLSCertCallback(cb TLSCertCallback) {
	r.tlsReadyOnce.Do(func() {
		r.tlsCertCallback = cb
		close(r.tlsReadyCh)
	})
}

func (r *runtimeState) GetTLSCertCallback(ctx context.Context) (TLSCertCallback, error) {
	select {
	case <-r.tlsReadyCh:
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
	return &runtimeState{
		haltCh:      make(chan struct{}),
		tlsReadyCh:  make(chan struct{}),
		listenErrCh: make(chan error, 3),
		childDoneCh: make(chan error),
	}
}
