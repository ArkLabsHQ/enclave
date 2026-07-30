package cli

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var migrationPCR0Pattern = regexp.MustCompile(`^[0-9a-f]{96}$`)

const (
	migrationControlTimeout  = 90 * time.Second
	migrationFinaliseTimeout = 12 * time.Minute
)

type migrationOptions struct {
	region         string
	profile        string
	instanceID     string
	supervisorURL  string
	enclaveURL     string
	targetPCR0     string
	artifactBucket string
	eifKey         string
	supervisorKey  string
	secretNames    []string
}

type migrationStatus struct {
	State            string `json:"state"`
	SourcePCR0       string `json:"source_pcr0"`
	TargetPCR0       string `json:"target_pcr0"`
	Sequence         uint64 `json:"sequence"`
	Action           string `json:"action"`
	PublishedAt      string `json:"published_at"`
	EligibleAt       string `json:"eligible_at"`
	RemainingSeconds int    `json:"remaining_seconds"`
}

type migrationEvent struct {
	Step    int    `json:"step"`
	Total   int    `json:"total"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type migrationTransport interface {
	Do(context.Context, string, string, []byte) (*http.Response, error)
}

func migrationCmd() *cobra.Command {
	var opts migrationOptions
	cmd := &cobra.Command{
		Use:   "migration",
		Short: "Manage enclave migration",
	}

	cmd.PersistentFlags().StringVar(&opts.region, "region", "", "AWS region (defaults to enclave.yaml)")
	cmd.PersistentFlags().StringVar(&opts.profile, "profile", "", "AWS named profile (defaults to enclave.yaml)")
	cmd.PersistentFlags().StringVar(&opts.instanceID, "instance-id", "", "EC2 instance ID (defaults to Tofu output)")
	cmd.PersistentFlags().StringVar(&opts.supervisorURL, "supervisor-url", "", "direct supervisor URL (local mode, usually http://127.0.0.1:8444)")
	cmd.PersistentFlags().StringVar(&opts.enclaveURL, "enclave-url", "", "direct enclave URL for status (local mode, usually https://127.0.0.1:8443)")
	cmd.PersistentFlags().StringVar(&opts.targetPCR0, "target-pcr0", "", "candidate PCR0 (defaults to Tofu output)")
	cmd.PersistentFlags().StringVar(&opts.artifactBucket, "artifact-bucket", "", "candidate artifact S3 bucket (defaults to Tofu output)")
	cmd.PersistentFlags().StringVar(&opts.eifKey, "eif-key", "", "candidate EIF S3 key (defaults to Tofu output)")
	cmd.PersistentFlags().StringVar(&opts.supervisorKey, "supervisor-key", "", "candidate supervisor S3 key (defaults to Tofu output)")

	cmd.AddCommand(
		&cobra.Command{
			Use:   "request",
			Short: "Publish a migration request",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runMigrationRequest(cmd, opts)
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show current migration state",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runMigrationStatus(cmd, opts)
			},
		},
		&cobra.Command{
			Use:   "abort",
			Short: "Abort the current migration request",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runMigrationAbort(cmd, opts)
			},
		},
	)

	var resume bool
	finalise := &cobra.Command{
		Use:   "finalise",
		Short: "Finalise and activate the candidate enclave",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrationFinalise(cmd, opts, resume)
		},
	}
	finalise.Flags().BoolVar(&resume, "resume", false, "resume host activation without repeating enclave finalisation")
	cmd.AddCommand(finalise)

	return cmd
}

func runMigrationRequest(cmd *cobra.Command, opts migrationOptions) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), migrationControlTimeout)
	defer cancel()

	resolved, err := resolveMigration(ctx, opts, "request")
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		TargetPCR0 string `json:"target_pcr0"`
	}{TargetPCR0: resolved.targetPCR0})
	if err != nil {
		return err
	}

	if err := printMigrationResolution(cmd.OutOrStdout(), resolved, false); err != nil {
		return err
	}
	transport, err := newMigrationTransport(ctx, resolved, false)
	if err != nil {
		return err
	}
	return runMigrationStatusRequest(ctx, cmd.OutOrStdout(), transport, http.MethodPost, "/migrate/request", body)
}

func runMigrationStatus(cmd *cobra.Command, opts migrationOptions) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), migrationControlTimeout)
	defer cancel()

	resolved, err := resolveMigration(ctx, opts, "status")
	if err != nil {
		return err
	}
	transport, err := newMigrationTransport(ctx, resolved, true)
	if err != nil {
		return err
	}
	resp, err := transport.Do(ctx, http.MethodGet, "/v1/enclave-info", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read migration status: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return migrationProtocolError(resp.StatusCode, data)
	}
	var info struct {
		Migration *migrationStatus `json:"migration"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("decode enclave migration status: %w", err)
	}
	if info.Migration == nil {
		return errors.New("enclave info response is missing migration status")
	}
	if err := validateMigrationState(info.Migration.State); err != nil {
		return err
	}
	return printMigrationStatus(cmd.OutOrStdout(), *info.Migration)
}

func runMigrationAbort(cmd *cobra.Command, opts migrationOptions) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), migrationControlTimeout)
	defer cancel()

	resolved, err := resolveMigration(ctx, opts, "abort")
	if err != nil {
		return err
	}
	if err := printMigrationResolution(cmd.OutOrStdout(), resolved, false); err != nil {
		return err
	}
	transport, err := newMigrationTransport(ctx, resolved, false)
	if err != nil {
		return err
	}
	return runMigrationStatusRequest(ctx, cmd.OutOrStdout(), transport, http.MethodPost, "/migrate/abort", nil)
}

func runMigrationFinalise(cmd *cobra.Command, opts migrationOptions, resume bool) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), migrationFinaliseTimeout)
	defer cancel()

	resolved, err := resolveMigration(ctx, opts, "finalise")
	if err != nil {
		return err
	}
	if len(resolved.secretNames) == 0 {
		return errors.New("finalise requires at least one configured secret name")
	}
	body, err := json.Marshal(struct {
		Finalize               bool     `json:"finalize"`
		EIFBucket              string   `json:"eif_bucket"`
		EIFKey                 string   `json:"eif_key"`
		PCR0                   string   `json:"pcr0"`
		SecretNames            []string `json:"secret_names"`
		SupervisorBinaryBucket string   `json:"supervisor_binary_bucket"`
		SupervisorBinaryKey    string   `json:"supervisor_binary_key"`
	}{
		Finalize:               !resume,
		EIFBucket:              resolved.artifactBucket,
		EIFKey:                 resolved.eifKey,
		PCR0:                   resolved.targetPCR0,
		SecretNames:            resolved.secretNames,
		SupervisorBinaryBucket: resolved.artifactBucket,
		SupervisorBinaryKey:    resolved.supervisorKey,
	})
	if err != nil {
		return err
	}

	if err := printMigrationResolution(cmd.OutOrStdout(), resolved, !resume); err != nil {
		return err
	}
	transport, err := newMigrationTransport(ctx, resolved, false)
	if err != nil {
		return err
	}
	resp, err := transport.Do(ctx, http.MethodPost, "/migrate", body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("read migration error response: %w", readErr)
		}
		return migrationProtocolError(resp.StatusCode, data)
	}
	return consumeMigrationEvents(resp.Body, cmd.OutOrStdout())
}

func runMigrationStatusRequest(ctx context.Context, w io.Writer, transport migrationTransport, method, path string, body []byte) error {
	resp, err := transport.Do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read migration response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return migrationProtocolError(resp.StatusCode, data)
	}
	var status migrationStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("decode migration response: %w", err)
	}
	if err := validateMigrationState(status.State); err != nil {
		return err
	}
	return printMigrationStatus(w, status)
}

func resolveMigration(ctx context.Context, opts migrationOptions, operation string) (migrationOptions, error) {
	cfg, err := loadConfig()
	if err != nil {
		return migrationOptions{}, err
	}
	root, err := findRepoRoot()
	if err != nil {
		return migrationOptions{}, err
	}

	var needOutputs bool
	switch operation {
	case "status":
		needOutputs = opts.enclaveURL == "" && opts.instanceID == ""
	case "abort":
		needOutputs = opts.supervisorURL == "" && opts.instanceID == ""
	case "request":
		needOutputs = (opts.supervisorURL == "" && opts.instanceID == "") || opts.targetPCR0 == ""
	case "finalise":
		needOutputs = (opts.supervisorURL == "" && opts.instanceID == "") || opts.targetPCR0 == "" ||
			opts.artifactBucket == "" || opts.eifKey == "" || opts.supervisorKey == ""
	default:
		return migrationOptions{}, fmt.Errorf("unknown migration operation %q", operation)
	}

	outputs := TofuOutputs{}
	var outputErr error
	if needOutputs {
		outputs, outputErr = loadTofuOutputsContext(ctx, root)
		if ctx.Err() != nil {
			return migrationOptions{}, ctx.Err()
		}
	}
	resolved, err := resolveMigrationValues(root, cfg, outputs, opts, operation)
	if err != nil {
		if outputErr != nil {
			return migrationOptions{}, fmt.Errorf("%w (Tofu outputs unavailable: %v)", err, outputErr)
		}
		return migrationOptions{}, err
	}
	return resolved, nil
}

func resolveMigrationValues(root string, cfg *Config, outputs TofuOutputs, opts migrationOptions, operation string) (migrationOptions, error) {
	var err error
	resolved := opts
	resolved.region = cmp.Or(opts.region, cfg.Region)
	resolved.profile = cmp.Or(opts.profile, cfg.Profile)
	resolved.instanceID = cmp.Or(opts.instanceID, outputs.getOutput("instance_id"))
	resolved.targetPCR0 = cmp.Or(opts.targetPCR0, outputs.getOutput("candidate_pcr0"))
	resolved.artifactBucket = cmp.Or(opts.artifactBucket, outputs.getOutput("candidate_artifact_bucket"))
	resolved.eifKey = cmp.Or(opts.eifKey, outputs.getOutput("candidate_eif_key"))
	resolved.supervisorKey = cmp.Or(opts.supervisorKey, outputs.getOutput("candidate_supervisor_key"))
	resolved.secretNames = nil
	for _, secret := range cfg.Secrets {
		resolved.secretNames = append(resolved.secretNames, secret.Name)
	}

	if operation == "status" {
		if resolved.enclaveURL != "" {
			resolved.enclaveURL, err = normalizeMigrationURL("--enclave-url", resolved.enclaveURL)
			if err != nil {
				return migrationOptions{}, err
			}
		} else if resolved.instanceID == "" {
			return migrationOptions{}, errors.New("instance ID is required (set --instance-id or run tofu apply, or use --enclave-url for local mode)")
		} else if resolved.region == "" {
			return migrationOptions{}, errors.New("AWS region is required (set --region or enclave.yaml region)")
		}
		return resolved, nil
	}

	if resolved.supervisorURL != "" {
		resolved.supervisorURL, err = normalizeMigrationURL("--supervisor-url", resolved.supervisorURL)
		if err != nil {
			return migrationOptions{}, err
		}
	} else if resolved.instanceID == "" {
		return migrationOptions{}, errors.New("instance ID is required (set --instance-id or run tofu apply, or use --supervisor-url for local mode)")
	} else if resolved.region == "" {
		return migrationOptions{}, errors.New("AWS region is required (set --region or enclave.yaml region)")
	}
	if operation == "abort" {
		return resolved, nil
	}
	if resolved.targetPCR0 == "" {
		resolved.targetPCR0, err = readArtifactPCR0(filepath.Join(root, ".enclave", "artifacts", "pcr.json"))
		if err != nil {
			return migrationOptions{}, fmt.Errorf("candidate PCR0 is required (set --target-pcr0, run tofu apply, or provide .enclave/artifacts/pcr.json): %w", err)
		}
	}
	resolved.targetPCR0, err = normalizePCR0(resolved.targetPCR0)
	if err != nil {
		return migrationOptions{}, err
	}
	if operation == "request" {
		return resolved, nil
	}
	for name, value := range map[string]string{
		"candidate artifact bucket": resolved.artifactBucket,
		"candidate EIF key":         resolved.eifKey,
		"candidate supervisor key":  resolved.supervisorKey,
	} {
		if strings.TrimSpace(value) == "" {
			return migrationOptions{}, fmt.Errorf("%s is required (set its override flag or run tofu apply)", name)
		}
	}
	return resolved, nil
}

func normalizeMigrationURL(flag, value string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/")
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s must be an http(s) base URL", flag)
	}
	return value, nil
}

func normalizePCR0(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !migrationPCR0Pattern.MatchString(value) {
		return "", errors.New("target PCR0 must be exactly 96 hexadecimal characters")
	}
	return value, nil
}

func readArtifactPCR0(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var artifact PCRValues
	if err := json.Unmarshal(data, &artifact); err != nil {
		return "", fmt.Errorf("decode %s: %w", path, err)
	}
	return normalizePCR0(artifact.PCR0)
}

func newMigrationTransport(ctx context.Context, resolved migrationOptions, status bool) (migrationTransport, error) {
	if status && resolved.enclaveURL != "" {
		return &directMigrationTransport{baseURL: resolved.enclaveURL, insecureTLS: true}, nil
	}
	if !status && resolved.supervisorURL != "" {
		return &directMigrationTransport{baseURL: resolved.supervisorURL}, nil
	}
	ac, err := newAWSClients(ctx, resolved.region, resolved.profile)
	if err != nil {
		return nil, err
	}
	return &ssmMigrationTransport{aws: ac, instanceID: resolved.instanceID}, nil
}

type directMigrationTransport struct {
	baseURL     string
	insecureTLS bool
}

func (t *directMigrationTransport) Do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, t.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create migration request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: t.insecureTLS}}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("migration request failed: %w", err)
	}
	return resp, nil
}

type ssmMigrationTransport struct {
	aws        *awsClients
	instanceID string
}

func (t *ssmMigrationTransport) Do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	remotePort, scheme, insecureTLS := supervisorRemotePort, "http", false
	if path == "/v1/enclave-info" {
		remotePort, scheme, insecureTLS = "443", "https", true
	}
	starter := t.aws.sessions
	if starter == nil {
		starter = cmdSessionStarter{}
	}
	port, cleanup, err := starter.StartPortForward(ctx, t.instanceID, t.aws.region, t.aws.profile, remotePort)
	if err != nil {
		return nil, err
	}
	transport := &directMigrationTransport{
		baseURL:     fmt.Sprintf("%s://127.0.0.1:%d", scheme, port),
		insecureTLS: insecureTLS,
	}
	resp, err := transport.Do(ctx, method, path, body)
	if err != nil {
		cleanup()
		return nil, err
	}
	resp.Body = sessionClosingBody{rc: resp.Body, cleanup: cleanup}
	return resp, nil
}

func migrationProtocolError(statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))
	if message == "" {
		return fmt.Errorf("HTTP %d", statusCode)
	}
	return fmt.Errorf("HTTP %d: %s", statusCode, message)
}

func validateMigrationState(state string) error {
	switch state {
	case "none", "cooling_down", "eligible", "aborted":
		return nil
	default:
		return fmt.Errorf("unknown migration state %q", state)
	}
}

func printMigrationResolution(w io.Writer, resolved migrationOptions, finalise bool) error {
	lines := []string{
		"Resolved migration:",
		fmt.Sprintf("  Region:                 %s", resolved.region),
		fmt.Sprintf("  Profile:                %s", orUnset(resolved.profile)),
	}
	if resolved.supervisorURL != "" {
		lines = append(lines,
			"  Instance ID:            <direct>",
			fmt.Sprintf("  Supervisor URL:         %s", resolved.supervisorURL),
		)
	} else {
		lines = append(lines,
			fmt.Sprintf("  Instance ID:            %s", resolved.instanceID),
			"  Supervisor URL:         http://127.0.0.1:8443 (via SSM)",
		)
	}
	if resolved.targetPCR0 != "" {
		lines = append(lines, fmt.Sprintf("  Target PCR0:            %s", resolved.targetPCR0))
	}
	if resolved.artifactBucket != "" {
		lines = append(lines,
			fmt.Sprintf("  Candidate EIF:          s3://%s/%s", resolved.artifactBucket, resolved.eifKey),
			fmt.Sprintf("  Candidate supervisor:   s3://%s/%s", resolved.artifactBucket, resolved.supervisorKey),
			fmt.Sprintf("  Enclave finalisation:   %t", finalise),
		)
	}
	_, err := fmt.Fprintln(w, strings.Join(lines, "\n"))
	return err
}

func printMigrationStatus(w io.Writer, status migrationStatus) error {
	_, err := fmt.Fprintf(w, `Migration status:
  State:              %s
  Source PCR0:        %s
  Target PCR0:        %s
  Sequence:           %d
  Action:             %s
  Published at:       %s
  Eligible at:        %s
  Remaining seconds:  %d
`, status.State, orUnset(status.SourcePCR0), orUnset(status.TargetPCR0), status.Sequence,
		orUnset(status.Action), orUnset(status.PublishedAt), orUnset(status.EligibleAt), status.RemainingSeconds)
	return err
}

func consumeMigrationEvents(r io.Reader, w io.Writer) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	var lastStatus string
	var failure string
	for {
		var event migrationEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed migration event: %w", err)
		}
		switch event.Status {
		case "progress", "warn", "complete":
		case "error", "rollback", "rollback-complete":
			if failure == "" {
				failure = event.Message
			}
		default:
			return fmt.Errorf("malformed migration event: unknown status %q", event.Status)
		}
		if _, err := fmt.Fprintf(w, "[%d/%d] %s: %s\n", event.Step, event.Total, event.Status, event.Message); err != nil {
			return fmt.Errorf("write migration event: %w", err)
		}
		lastStatus = event.Status
	}
	if failure != "" {
		return fmt.Errorf("migration failed: %s", failure)
	}
	if lastStatus != "complete" {
		return fmt.Errorf("migration stream ended without completion (last status %q)", lastStatus)
	}
	return nil
}

func orUnset(s string) string {
	return cmp.Or(s, "<unset>")
}
