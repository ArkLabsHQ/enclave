package introspector_enclave

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func deployCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deploy",
		Short: "Deploy or upgrade the enclave",
		Long: `Deploy a new EIF to a running enclave instance.

Fresh deploy: CDK deploy → wait for instance → enclave self-applies KMS policy.
Upgrade: Create new KMS key → export secrets via old enclave → restart → new enclave self-locks.

The enclave applies its own KMS key policy using hardware-attested PCR0 from NSM,
removing the CLI from the trust chain. The key is automatically locked (no PutKeyPolicy
for anyone) after each deploy.

Requires 'enclave build' to have been run first (enclave/artifacts/pcr.json and enclave/artifacts/image.eif).`,
		RunE: runDeploy,
	}
}

func runDeploy(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := cfg.validateSDK(); err != nil {
		return err
	}

	local := os.Getenv("LOCAL_DEPLOYMENT") == "true"
	ctx := context.Background()

	var root string
	var ac *awsClients

	if local {
		var err error
		root, err = findAppRoot()
		if err != nil {
			return err
		}

		// Copy app env, letting real environment variables override enclave.yaml
		// values. This is needed because enclave.yaml uses addresses reachable
		// from inside the QEMU enclave (e.g. host.containers.internal) while
		// the CLI runs outside QEMU and needs host-local addresses.
		appEnv := make(map[string]string)
		for k, v := range cfg.App.Env {
			appEnv[k] = v
		}
		for _, key := range []string{
			"AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL_SSM",
			"AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_S3",
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		} {
			if v := os.Getenv(key); v != "" {
				appEnv[key] = v
			}
		}
		ac, err = newAWSClientsWithEnv(ctx, cfg.Region, "", appEnv)
		if err != nil {
			return err
		}
	} else {
		if err := cfg.validateAccount(); err != nil {
			return err
		}
		var err error
		root, err = findRepoRoot()
		if err != nil {
			return err
		}
		ac, err = newAWSClients(ctx, cfg.Region, cfg.Profile)
		if err != nil {
			return err
		}
	}

	// Step 1: Read PCR0 from build artifacts.
	pcr0, err := readPCR0(root)
	if err != nil {
		return err
	}
	if pcr0 != "" {
		fmt.Printf("[deploy] PCR0 from build: %s\n", pcr0)
	}

	// Step 2: Detect upgrade mode.
	// An upgrade is when secrets have been initialized (KMSKeyID set in SSM).
	// This is the definitive signal — if the KMS key is set, a prior deploy
	// locked it to a PCR0 and we need the full migration flow.
	stack := cfg.stackName()
	isUpgrade := false
	kmsKey, _ := ac.getParameter(ctx, cfg.ssmParam("KMSKeyID"))
	if kmsKey != "" && kmsKey != "UNSET" {
		isUpgrade = true
	}

	if isUpgrade {
		fmt.Printf("\n[deploy] Upgrade mode (KMS key exists)\n\n")

		outputs, err := loadCDKOutputs(root)
		if err != nil {
			return err
		}

		instanceID := outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
		ec2RoleARN := outputs.getOutput(stack, "EC2InstanceRoleARN")

		return deployUpgrade(ctx, ac, cfg, root, pcr0, instanceID, ec2RoleARN, local)
	}

	if local {
		fmt.Println("[deploy] Local mode (localstack)")
		// CDK deploy first (idempotent).
		return runCDKDeploy(cfg, root)

	}

	fmt.Printf("\n[deploy] Fresh deploy\n\n")
	return deployFresh(ctx, ac, cfg, root, pcr0)
}

// deployFresh handles first-time deployment: CDK deploy → wait for instance.
// The enclave self-applies its KMS policy during Init() using hardware-attested PCR0.
func deployFresh(ctx context.Context, ac *awsClients, cfg *Config, root, pcr0 string) error {
	// Synthesize and deploy the CDK stack.
	if err := runCDKDeploy(cfg, root); err != nil {
		return err
	}

	// Read outputs.
	outputs, err := loadCDKOutputs(root)
	if err != nil {
		return err
	}

	stack := cfg.stackName()
	instanceID := outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
	if instanceID == "" {
		return fmt.Errorf("InstanceID not found in cdk-outputs.json for %s", stack)
	}

	// Wait for instance to be ready.
	fmt.Printf("[deploy] Waiting for instance %s to be ready...\n", instanceID)
	if err := ac.waitInstanceReady(ctx, instanceID); err != nil {
		return fmt.Errorf("waiting for instance: %w", err)
	}

	elasticIP := outputs.getOutput(stack, "ElasticIP", "Elastic IP")

	// Persist instance ID and elastic IP in SSM so they're available across
	// CI runs (cdk-outputs.json is gitignored and not present during upgrades
	// or destroy).
	_ = ac.putParameter(ctx, cfg.ssmParam("InstanceID"), instanceID)
	if elasticIP != "" {
		_ = ac.putParameter(ctx, cfg.ssmParam("ElasticIP"), elasticIP)
	}

	fmt.Println()
	fmt.Println("[deploy] Done.")
	fmt.Printf("  Instance ID: %s\n", instanceID)
	fmt.Printf("  Elastic IP:  %s\n", elasticIP)
	fmt.Printf("  PCR0:        %s\n", pcr0)

	fmt.Printf("\n[deploy] Verifying deployment (waiting up to 120s)...\n")
	if err := initialVerification(elasticIP, pcr0, 120); err != nil {
		fmt.Printf("[deploy] Warning: verification did not pass: %v\n", err)
		fmt.Println("[deploy] Try: enclave verify --wait 300")
	}

	return nil
}

// createUpgradeBucket creates an S3 bucket, grants the EC2 role read access,
// and uploads the new EIF. Returns the bucket name.
func createUpgradeBucket(ctx context.Context, ac *awsClients, cfg *Config, root, ec2RoleARN string) (string, error) {
	// Create S3 bucket for EIF transfer (idempotent).
	eifBucket := cfg.eifBucket()
	if err := ac.ensureBucket(ctx, eifBucket); err != nil {
		return "", fmt.Errorf("create EIF bucket: %w", err)
	}

	// Grant EC2 role read access to the bucket.
	bucketPolicy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": %q},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::%s/*"
  }]
}`, ec2RoleARN, eifBucket)

	if err := ac.putBucketPolicy(ctx, eifBucket, bucketPolicy); err != nil {
		return "", fmt.Errorf("set bucket policy: %w", err)
	}

	// Upload new EIF.
	eifPath := filepath.Join(root, "enclave", "artifacts", "image.eif")
	if _, err := os.Stat(eifPath); os.IsNotExist(err) {
		return "", fmt.Errorf("enclave/artifacts/image.eif not found (run 'enclave build' first)")
	}

	fmt.Printf("[deploy] Uploading new EIF to s3://%s/image.eif ...\n", eifBucket)
	if err := ac.uploadFile(ctx, eifBucket, "image.eif", eifPath); err != nil {
		return "", fmt.Errorf("upload EIF to S3: %w", err)
	}

	return eifBucket, nil

}

// deployUpgrade handles both local and production upgrades. Both paths upload
// the EIF to S3 and send the same payload to the mgmt server's /migrate endpoint.
// The only difference is transport: local calls mgmt directly via HTTP, production
// uses SSM RunCommand (since localstack doesn't support SendCommand).
func deployUpgrade(ctx context.Context, ac *awsClients, cfg *Config, root, pcr0, instanceID, ec2RoleARN string, local bool) error {
	// Step 1: Upload EIF to S3.
	fmt.Println("[deploy] Uploading EIF to S3...")
	eifBucket, err := createUpgradeBucket(ctx, ac, cfg, root, ec2RoleARN)
	if err != nil {
		return err
	}

	// Step 2: Build migration payload.
	secretNames := make([]string, len(cfg.Secrets))
	for i, s := range cfg.Secrets {
		secretNames[i] = fmt.Sprintf("%q", s.Name)
	}
	migrateJSON := fmt.Sprintf(`{"eif_bucket":%q,"eif_key":"image.eif","pcr0":%q,"secret_names":[%s]}`,
		eifBucket, pcr0, strings.Join(secretNames, ","))

	// Step 3: Trigger migration on mgmt server.
	if local {
		// Local: call mgmt directly via HTTP (localstack doesn't support SSM RunCommand).
		mgmtURL := os.Getenv("ENCLAVE_MGMT_URL")
		if mgmtURL == "" {
			mgmtURL = "http://localhost:8444"
		}
		fmt.Printf("[deploy] Calling mgmt server at %s/migrate ...\n", mgmtURL)
		if err := callMgmtMigrateDirect(ctx, mgmtURL, migrateJSON); err != nil {
			return err
		}
	} else {
		// Production: trigger via SSM RunCommand on the EC2 host.
		fmt.Println("[deploy] Triggering migration on host via SSM RunCommand...")
		migrateCmd := fmt.Sprintf(`curl -sf -X POST http://localhost:8443/migrate -H 'Content-Type: application/json' -d '%s'`, migrateJSON)
		if err := ac.runOnHost(ctx, instanceID, "migrate enclave", []string{migrateCmd}); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	fmt.Println()
	fmt.Println("[deploy] Migration complete.")
	fmt.Printf("  PCR0: %s\n", pcr0)

	// Step 4: Verify the upgrade.
	var verifyHost string
	if local {
		// Strip scheme — initialVerification prepends "https://".
		u := localEnclaveURL()
		verifyHost = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	} else {
		verifyHost, _ = ac.getParameter(ctx, cfg.ssmParam("ElasticIP"))
	}
	if verifyHost != "" {
		fmt.Printf("\n[deploy] Verifying upgrade (waiting up to 60s)...\n")
		if err := initialVerification(verifyHost, pcr0, 60); err != nil {
			fmt.Printf("[deploy] Warning: verification did not pass: %v\n", err)
			if !local {
				fmt.Println("[deploy] Try: enclave verify --wait 300")
			}
		}
	}

	return nil
}

// callMgmtMigrateDirect calls the mgmt server's /migrate endpoint directly via HTTP.
// The handler streams NDJSON status lines; errors are indicated via "status":"error"
// in the last line (HTTP status is always 200 since headers are sent before steps run).
func callMgmtMigrateDirect(ctx context.Context, mgmtURL, payload string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mgmtURL+"/migrate",
		strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 180 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call mgmt /migrate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mgmt /migrate returned %d: %s", resp.StatusCode, string(body))
	}

	// Stream NDJSON status lines to stdout and check for errors.
	body, _ := io.ReadAll(resp.Body)
	fmt.Print(string(body))

	// Check last NDJSON line for error status.
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) > 0 {
		var last struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(lines[len(lines)-1]), &last) == nil && last.Status == "error" {
			return fmt.Errorf("migration failed: %s", last.Message)
		}
	}

	return nil
}

// --- Local helpers ---

// localEnclaveURL returns the base URL for the local QEMU enclave.
func localEnclaveURL() string {
	if url := os.Getenv("ENCLAVE_URL"); url != "" {
		return url
	}
	port := os.Getenv("HOST_TLS_PORT")
	if port == "" {
		port = "8443"
	}
	return "https://localhost:" + port
}

// --- Post-deploy verification ---

// initialVerification runs attestation verification with retry against a
// freshly deployed enclave. Reuses the same checks as `enclave verify`.
func initialVerification(elasticIP, pcr0 string, waitSeconds int) error {
	client := verifyHTTPClient(true)
	baseURL := "https://" + elasticIP

	runAllChecks := func() error {
		result, err := verifyAttestation(client, baseURL, pcr0)
		if err != nil {
			return err
		}
		if err := verifyAttestationKeyBinding(client, baseURL, result); err != nil {
			return err
		}
		if err := verifyPCR0Chain(client, baseURL); err != nil {
			return fmt.Errorf("PCR0 chain: %w", err)
		}
		return nil
	}

	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	interval := 5 * time.Second
	attempt := 0

	for {
		attempt++
		err := runAllChecks()
		if err == nil {
			fmt.Println("[deploy] Verification passed.")
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		remaining := time.Until(deadline).Truncate(time.Second)
		fmt.Printf("[deploy] Attempt %d failed (%s), retrying... (%s remaining)\n",
			attempt, shortErr(err), remaining)
		time.Sleep(interval)
	}
}

// --- File helpers ---

// readPCR0 reads the PCR0 value from artifacts/pcr.json.
func readPCR0(root string) (string, error) {
	pcrPath := filepath.Join(root, "enclave", "artifacts", "pcr.json")
	data, err := os.ReadFile(pcrPath)
	if err != nil {
		return "", fmt.Errorf("enclave/artifacts/pcr.json not found (run 'enclave build' first)")
	}
	var pcrs PCRValues
	if err := json.Unmarshal(data, &pcrs); err != nil {
		return "", fmt.Errorf("parse pcr.json: %w", err)
	}
	if pcrs.PCR0 == "" {
		return "", fmt.Errorf("PCR0 is empty in artifacts/pcr.json")
	}
	return pcrs.PCR0, nil
}

// --- Config helpers ---

// ssmParam returns the full SSM parameter path for a given parameter name.
func (c *Config) ssmParam(name string) string {
	return fmt.Sprintf("/%s/%s/%s", c.Prefix, c.Name, name)
}

// eifBucket returns the S3 bucket name used for EIF transfers during upgrades.
func (c *Config) eifBucket() string {
	return fmt.Sprintf("%s-%s-eif-%s-%s", c.Prefix, c.Name, c.Account, c.Region)
}
