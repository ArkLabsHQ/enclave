// runner is the entrypoint baked into the enclave-test-runner image:
// seed SSM, bring up vsock + heartbeat, spawn the supervisor whose
// watchdog re-execs this binary as `runner --boot-only <eif>` to fire
// QEMU. Replaces test/run.sh for upstream-app testing; the framework's
// own integration-test suite still uses run.sh.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const (
	heartbeatPort = 9000
	heartbeatByte = 0xB7
	vsockCID      = 4
	vsockSocket   = "/tmp/vhost4.socket"
)

func main() {
	bootOnly := flag.String("boot-only", "", "boot QEMU with the given EIF path and exit (used by supervisor's ENCLAVE_START_CMD)")
	flag.Parse()

	if *bootOnly != "" {
		if err := bootQEMU(*bootOnly); err != nil {
			log.Fatalf("boot qemu: %v", err)
		}
		return
	}

	if err := run(); err != nil {
		log.Fatalf("runner: %v", err)
	}
}

func run() error {
	eifPath := envOr("EIF_PATH", "/data/image.eif")
	if _, err := os.Stat(eifPath); err != nil {
		return fmt.Errorf("EIF not found at %s — mount your image into /data/image.eif: %w", eifPath, err)
	}

	deployment := envOr("ENCLAVE_DEPLOYMENT", "dev")
	appName := envOr("ENCLAVE_APP_NAME", "")
	if appName == "" {
		return errors.New("ENCLAVE_APP_NAME must be set (matches enclave.yaml `name:`)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := seedSSM(ctx, deployment, appName); err != nil {
		return fmt.Errorf("seed SSM: %w", err)
	}

	vsock, err := startVsock(ctx)
	if err != nil {
		return fmt.Errorf("start vsock device: %w", err)
	}
	defer kill(vsock)

	go runHeartbeat(ctx)

	sup, err := startSupervisor(ctx, eifPath)
	if err != nil {
		return fmt.Errorf("start supervisor: %w", err)
	}

	log.Printf("runner: stack up; waiting for supervisor (PID %d). Send SIGTERM to tear down.", sup.Process.Pid)
	err = sup.Wait()
	if err != nil && ctx.Err() == nil {
		return fmt.Errorf("supervisor exited: %w", err)
	}
	return nil
}

// seedSSM writes the KMSKeyID placeholder so EnsureKeyID can self-create
// the real key on first boot. Idempotent on the placeholder; never
// overwrites a registered key.
func seedSSM(ctx context.Context, deployment, appName string) error {
	endpoint := envOr("AWS_ENDPOINT_URL_SSM", "http://localstack:4566")
	region := envOr("AWS_REGION", "us-east-1")

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}
	cli := ssm.NewFromConfig(cfg, func(o *ssm.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	paramName := fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)
	get, getErr := cli.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(paramName)})
	if getErr == nil && get.Parameter != nil && aws.ToString(get.Parameter.Value) != "" {
		log.Printf("ssm: %s already present (=%q), skipping seed", paramName, aws.ToString(get.Parameter.Value))
		return nil
	}

	_, err = cli.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}
	log.Printf("ssm: seeded %s = UNSET", paramName)
	return nil
}

func startVsock(ctx context.Context) (*exec.Cmd, error) {
	_ = os.Remove(vsockSocket)
	args := []string{
		"--vm",
		fmt.Sprintf("guest-cid=%d,socket=%s,forward-cid=1,forward-listen=9001+9002", vsockCID, vsockSocket),
	}
	cmd := exec.CommandContext(ctx, "vhost-device-vsock", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	time.Sleep(1 * time.Second)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return nil, fmt.Errorf("vhost-device-vsock exited immediately")
	}
	log.Printf("vsock: vhost-device-vsock up (PID %d, socket %s, CID %d)", cmd.Process.Pid, vsockSocket, vsockCID)
	return cmd, nil
}

func runHeartbeat(ctx context.Context) {
	if err := serveHeartbeat(ctx); err != nil && ctx.Err() == nil {
		log.Printf("heartbeat: %v", err)
	}
}

func startSupervisor(ctx context.Context, eifPath string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate runner binary: %w", err)
	}

	// The supervisor's watchdog fires this string to (re-)launch QEMU;
	// re-execing ourselves keeps QEMU args in one place.
	startCmd := fmt.Sprintf(`nohup %q --boot-only %q >> /tmp/boot-qemu.log 2>&1 &`, self, eifPath)

	env := append(os.Environ(),
		"ENCLAVE_SUPERVISOR_ADDR=127.0.0.1:8444",
		"GVPROXY_FORWARD_PORTS=8443:443 7073",
		"IMDS_PROXY_TARGET="+envOr("IMDS_PROXY_TARGET", "aws-mocks:1338"),
		"ENCLAVE_URL=https://127.0.0.1:8443",
		"ENCLAVE_EIF_PATH="+eifPath,
		"ENCLAVE_START_CMD="+startCmd,
		"ENCLAVE_STOP_CMD=pkill -f qemu-system-x86_64 || true; sleep 2",
	)

	cmd := exec.CommandContext(ctx, "supervisor")
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func bootQEMU(eifPath string) error {
	if _, err := os.Stat(eifPath); err != nil {
		return fmt.Errorf("EIF not found at %s: %w", eifPath, err)
	}
	mem := envOr("MEMORY", "4G")
	args := []string{
		"-M", "nitro-enclave,vsock=c,id=test-enclave",
		"-kernel", eifPath,
		"-nographic",
		"-m", mem,
		"-chardev", "socket,id=c,path=" + vsockSocket,
	}
	if _, err := os.Stat("/dev/kvm"); err == nil {
		args = append(args, "--enable-kvm", "-cpu", "host")
	} else {
		args = append(args, "-accel", "tcg", "-cpu", "max")
	}
	cmd := exec.Command("qemu-system-x86_64", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("qemu: booting %s (mem=%s)", eifPath, mem)
	return cmd.Run()
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// kill best-effort terminates a child process started by this runner.
func kill(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
}
