package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// awsClients holds initialized AWS SDK v2 clients for a specific region.
type awsClients struct {
	region    string
	profile   string // empty = default credential chain; passed to `aws ssm start-session --profile` subprocesses
	ec2Client *ec2.Client
	kmsClient *kms.Client
	ssmClient *ssm.Client
	s3Client  *s3.Client
	sessions  sessionStarter // opens SSM Session Manager port-forwards; tests swap in fakes
}

func newAWSClients(ctx context.Context, region, profile string) (*awsClients, error) {
	return newAWSClientsWithEnv(ctx, region, profile, nil)
}

// newAWSClientsWithEnv creates AWS clients, optionally overriding endpoints
// from the app env map (AWS_ENDPOINT_URL_KMS, AWS_ENDPOINT_URL_SSM, etc).
func newAWSClientsWithEnv(ctx context.Context, region, profile string, appEnv map[string]string) (*awsClients, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	ac := &awsClients{region: region, profile: profile}
	ac.ec2Client = ec2.NewFromConfig(cfg)

	if ep := appEnv["AWS_ENDPOINT_URL_KMS"]; ep != "" {
		ac.kmsClient = kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		ac.kmsClient = kms.NewFromConfig(cfg)
	}

	if ep := appEnv["AWS_ENDPOINT_URL_SSM"]; ep != "" {
		ac.ssmClient = ssm.NewFromConfig(cfg, func(o *ssm.Options) { o.BaseEndpoint = aws.String(ep) })
	} else {
		ac.ssmClient = ssm.NewFromConfig(cfg)
	}

	if ep := appEnv["AWS_ENDPOINT_URL_S3"]; ep != "" {
		ac.s3Client = s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
			o.UsePathStyle = true
		})
	} else {
		ac.s3Client = s3.NewFromConfig(cfg)
	}

	ac.sessions = cmdSessionStarter{}

	return ac, nil
}

// --- EC2 ---

func (ac *awsClients) getInstanceState(ctx context.Context, instanceID string) (string, error) {
	out, err := ac.ec2Client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", err
	}
	if len(out.Reservations) == 0 || len(out.Reservations[0].Instances) == 0 {
		return "", fmt.Errorf("instance %s not found", instanceID)
	}
	return string(out.Reservations[0].Instances[0].State.Name), nil
}

// runOnHost runs commands on the EC2 host via SSM Run Command and waits for completion.
func (ac *awsClients) runOnHost(ctx context.Context, instanceID, desc string, commands []string) error {
	fmt.Printf("[deploy] Running on host: %s\n", desc)

	out, err := ac.ssmClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": commands},
	})
	if err != nil {
		return fmt.Errorf("send SSM command: %w", err)
	}

	commandID := *out.Command.CommandId

	// Poll for completion (max 5 minutes).
	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)

		inv, err := ac.ssmClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			continue // invocation may not be ready yet
		}

		switch inv.Status {
		case ssmtypes.CommandInvocationStatusSuccess:
			fmt.Printf("[deploy] Done: %s\n", desc)
			return nil
		case ssmtypes.CommandInvocationStatusFailed,
			ssmtypes.CommandInvocationStatusTimedOut,
			ssmtypes.CommandInvocationStatusCancelled,
			ssmtypes.CommandInvocationStatusCancelling:
			if inv.StandardErrorContent != nil && *inv.StandardErrorContent != "" {
				fmt.Fprintf(os.Stderr, "%s\n", *inv.StandardErrorContent)
			}
			return fmt.Errorf("host command failed (%s): %s", inv.Status, desc)
		}
		// InProgress, Pending, Delayed — keep polling.
	}

	return fmt.Errorf("timed out waiting for host command: %s", desc)
}

// runCommandOutput runs a single command on the host and returns its stdout (best-effort).
func (ac *awsClients) runCommandOutput(ctx context.Context, instanceID, command string) string {
	out, err := ac.ssmClient.SendCommand(ctx, &ssm.SendCommandInput{
		InstanceIds:  []string{instanceID},
		DocumentName: aws.String("AWS-RunShellScript"),
		Parameters:   map[string][]string{"commands": {command}},
	})
	if err != nil {
		return ""
	}

	commandID := *out.Command.CommandId
	for i := 0; i < 5; i++ {
		time.Sleep(3 * time.Second)
		inv, err := ac.ssmClient.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{
			CommandId:  aws.String(commandID),
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			continue
		}
		if inv.Status == ssmtypes.CommandInvocationStatusSuccess {
			if inv.StandardOutputContent != nil {
				return strings.TrimSpace(*inv.StandardOutputContent)
			}
			return ""
		}
	}
	return ""
}

// SSM Session Manager port-forwarding transport. Replaces SSM RunCommand
// for log/trace/metrics so the 24KB stdout cap doesn't truncate responses.

type sessionStarter interface {
	StartPortForward(ctx context.Context, instanceID, region, profile, remotePort string) (localPort int, cleanup func(), err error)
}

var errPluginMissing = errors.New(
	"AWS SSM session-manager-plugin not found on PATH.\n" +
		"  macOS:  brew install --cask session-manager-plugin\n" +
		"  Linux:  https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html")

type cmdSessionStarter struct{}

func (s cmdSessionStarter) StartPortForward(ctx context.Context, instanceID, region, profile, remotePort string) (int, func(), error) {
	for attempt := 0; attempt < 2; attempt++ {
		port, cleanup, err := s.startOnce(ctx, instanceID, region, profile, remotePort)
		if err == nil {
			return port, cleanup, nil
		}
		if attempt == 0 && isPortRaceError(err) {
			continue
		}
		return 0, nil, err
	}
	return 0, nil, errors.New("aws ssm start-session: lost local-port race twice")
}

func isPortRaceError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "bind: address already")
}

func (cmdSessionStarter) startOnce(ctx context.Context, instanceID, region, profile, remotePort string) (int, func(), error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("alloc local port: %w", err)
	}
	localPort := lis.Addr().(*net.TCPAddr).Port
	_ = lis.Close()

	params := fmt.Sprintf(`{"portNumber":["%s"],"localPortNumber":["%d"]}`, remotePort, localPort)
	args := []string{"ssm", "start-session",
		"--target", instanceID,
		"--document-name", "AWS-StartPortForwardingSession",
		"--parameters", params,
		"--region", region,
	}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
	setProcessGroup(cmd)

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 0, nil, err
	}
	var stderrBuf bytes.Buffer
	stderrTee := io.TeeReader(stderrPipe, &stderrBuf)

	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return 0, nil, errors.New("aws CLI not found on PATH (required for SSM Session Manager); install AWS CLI v2")
		}
		return 0, nil, fmt.Errorf("start aws ssm start-session: %w", err)
	}

	exitedCh := make(chan error, 1)
	go func() { exitedCh <- cmd.Wait() }()

	// scannerDone gates reads of stderrBuf: cmd.Wait does not synchronize
	// with user-driven pipe reads, so anyone touching the buffer must wait
	// for the scanner to exit first.
	pluginErrCh := make(chan struct{}, 1)
	scannerDone := make(chan struct{})
	go func() {
		defer close(scannerDone)
		scanner := bufio.NewScanner(stderrTee)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "SessionManagerPlugin is not found") {
				select {
				case pluginErrCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	cleanup := func() {
		killProcessGroup(cmd)
		select {
		case <-exitedCh:
		case <-time.After(2 * time.Second):
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			<-exitedCh
		}
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-pluginErrCh:
			cleanup()
			return 0, nil, errPluginMissing
		case waitErr := <-exitedCh:
			<-scannerDone
			stderrTxt := strings.TrimSpace(stderrBuf.String())
			if stderrTxt == "" {
				return 0, nil, fmt.Errorf("aws ssm start-session exited: %w", waitErr)
			}
			return 0, nil, fmt.Errorf("aws ssm start-session exited (%v): %s", waitErr, stderrTxt)
		default:
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return localPort, cleanup, nil
		}
		time.Sleep(200 * time.Millisecond)
	}

	cleanup()
	return 0, nil, fmt.Errorf("port-forward session did not establish within 15s")
}

// sessionClosingBody binds the SSM session's lifetime to the response body:
// closing the body tears down the subprocess.
type sessionClosingBody struct {
	rc      io.ReadCloser
	cleanup func()
}

func (s sessionClosingBody) Read(p []byte) (int, error) { return s.rc.Read(p) }
func (s sessionClosingBody) Close() error {
	err := s.rc.Close()
	s.cleanup()
	return err
}

const supervisorRemotePort = "8443"

// Bounded header timeout, unbounded body streaming — log/trace responses
// can be megabytes; Body.Close is the caller's cancel lever.
var supervisorHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
	},
}

// httpViaSession opens a Session Manager port-forward to the supervisor and
// returns a streaming response. Caller must Close the Body to tear down the
// SSM session.
func (ac *awsClients) httpViaSession(ctx context.Context, instanceID, path string) (*http.Response, error) {
	starter := ac.sessions
	if starter == nil {
		starter = cmdSessionStarter{}
	}
	port, cleanup, err := starter.StartPortForward(ctx, instanceID, ac.region, ac.profile, supervisorRemotePort)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	if err != nil {
		cleanup()
		return nil, err
	}
	resp, err := supervisorHTTPClient.Do(req)
	if err != nil {
		cleanup()
		return nil, err
	}
	resp.Body = sessionClosingBody{rc: resp.Body, cleanup: cleanup}
	return resp, nil
}

func (ac *awsClients) fetchSupervisor(ctx context.Context, instanceID, path string) (io.ReadCloser, error) {
	resp, err := ac.httpViaSession(ctx, instanceID, path)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("supervisor returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

// Process-group helpers — needed because the AWS CLI spawns
// session-manager-plugin as a child; kill the group, not just the parent.
// Unix-only.

func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
