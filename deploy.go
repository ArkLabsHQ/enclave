package introspector_enclave

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	if err := cfg.validateAccount(); err != nil {
		return err
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	ctx := context.Background()
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	// Step 1: Read PCR0 from build artifacts.
	pcr0, err := readPCR0(root)
	if err != nil {
		return err
	}
	fmt.Printf("[deploy] PCR0 from build: %s\n", pcr0)

	// Step 2: Detect upgrade mode.
	// An upgrade is when the instance is already running with initialized secrets.
	stack := cfg.stackName()
	outputsPath := filepath.Join(root, "enclave", "cdk-outputs.json")

	isUpgrade := false
	var instanceID string

	if _, err := os.Stat(outputsPath); err == nil {
		outputs, err := loadCDKOutputs(root)
		if err == nil {
			instanceID = outputs.getOutput(stack, "InstanceID", "InstanceId", "Instance ID")
			if instanceID != "" {
				state, stateErr := ac.getInstanceState(ctx, instanceID)
				if stateErr == nil && state == "running" && len(cfg.Secrets) > 0 {
					cipher, _ := ac.getParameter(ctx, cfg.ssmParam(cfg.Secrets[0].Name+"/Ciphertext"))
					if cipher != "" && cipher != "UNSET" {
						isUpgrade = true
					}
				}
			}
		}
	}

	if isUpgrade {
		fmt.Printf("\n[deploy] Upgrade mode: existing enclave on %s\n\n", instanceID)

		outputs, err := loadCDKOutputs(root)
		if err != nil {
			return err
		}

		// Read current KMS key ID from SSM (may differ from CDK output after migration).
		kmsKeyID, _ := ac.getParameter(ctx, cfg.ssmParam("KMSKeyID"))
		if kmsKeyID == "" {
			kmsKeyID = outputs.getOutput(stack, "KMSKeyID", "KmsKeyId", "KMS Key ID")
		}

		ec2RoleARN := outputs.getOutput(stack, "EC2InstanceRoleARN")
		if kmsKeyID == "" || ec2RoleARN == "" {
			return fmt.Errorf("missing KMSKeyID or EC2InstanceRoleARN from CDK outputs")
		}

		return deployUpgrade(ctx, ac, cfg, root, pcr0, instanceID, kmsKeyID, ec2RoleARN)
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

// deployUpgrade handles upgrading an existing enclave.
func createUpgradeBucket(ctx context.Context, ac *awsClients, cfg *Config, root, pcr0, instanceID, kmsKeyID, ec2RoleARN string) (string, error) {
	// Create S3 bucket for EIF transfer (idempotent).
	eifBucket := cfg.eifBucket()
	ac.ensureBucket(ctx, eifBucket)

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
		return "", fmt.Errorf("enclave/artifacts/image.eif not found. Run 'enclave build' first.")
	}

	fmt.Printf("[deploy] Uploading new EIF to s3://%s/image.eif ...\n", eifBucket)
	if err := ac.uploadFile(ctx, eifBucket, "image.eif", eifPath); err != nil {
		return "", fmt.Errorf("upload EIF to S3: %w", err)
	}

	return eifBucket, nil

}

// deployUpgradeLocked handles migration when the KMS key is locked:
// create temp KMS key → export signing key from old enclave → restart with new key.
func deployUpgrade(ctx context.Context, ac *awsClients, cfg *Config, root string, pcr0, instanceID, kmsKeyID, ec2RoleARN string) error {
	fmt.Println("[deploy] Create Deploy s3 bucket")
	eifBucket, err := createUpgradeBucket(ctx, ac, cfg, root, pcr0, instanceID, kmsKeyID, ec2RoleARN)

	if err != nil {
		return err
	}

	fmt.Println("[deploy] KMS key is locked — using temporary key migration")

	// Step 1: Create new KMS key for the new enclave version.
	newKMSKeyID, err := ac.createKey(ctx,
		fmt.Sprintf("%s migration key for PCR0 %s...", cfg.Name, pcr0[:16]))
	if err != nil {
		return fmt.Errorf("create migration KMS key: %w", err)
	}
	fmt.Printf("[deploy] Created new KMS key: %s\n", newKMSKeyID)

	// Step 2: Apply transitional policy — Encrypt + admin (no Decrypt).
	// The new enclave will self-apply PCR0-restricted Decrypt during Init().
	if err := applyTransitionalKMSPolicy(ctx, ac, newKMSKeyID, ec2RoleARN, cfg.Account); err != nil {
		return fmt.Errorf("apply transitional policy to new KMS key: %w", err)
	}

	// Step 3: Store migration parameters in SSM.
	ssmParams := map[string]string{
		"MigrationKMSKeyID":    newKMSKeyID,
		"MigrationOldKMSKeyID": kmsKeyID,
	}
	for param, value := range ssmParams {
		if err := ac.putParameter(ctx, cfg.ssmParam(param), value); err != nil {
			return fmt.Errorf("store %s in SSM: %w", param, err)
		}
	}
	fmt.Println("[deploy] Migration KMS key IDs stored in SSM")

	// Step 4: Call old enclave's export endpoint via SSM.
	fmt.Println("[deploy] Calling old enclave's export endpoint...")
	exportCmd := `curl -sf -k -X POST https://127.0.0.1:443/v1/export-key`

	if err := ac.runOnHost(ctx, instanceID, "export secrets from old enclave", []string{exportCmd}); err != nil {
		fmt.Println("[deploy] Export failed, cleaning up")
		ac.resetParameter(ctx, cfg.ssmParam("MigrationKMSKeyID"))
		return fmt.Errorf("export secrets from old enclave: %w", err)
	}

	// Step 5: Wait for per-secret migration ciphertexts to appear in SSM.
	fmt.Println("[deploy] Waiting for migration ciphertexts...")
	maxWait := 60
	allFound := false
	for elapsed := 0; elapsed < maxWait; elapsed += 3 {
		found := 0
		for _, secret := range cfg.Secrets {
			ct, _ := ac.getParameter(ctx, cfg.ssmParam("Migration/"+secret.Name+"/Ciphertext"))
			if ct != "" && ct != "UNSET" {
				found++
			}
		}
		if found == len(cfg.Secrets) {
			allFound = true
			fmt.Printf("[deploy] All %d migration ciphertexts stored in SSM\n", found)
			break
		}
		time.Sleep(3 * time.Second)
		fmt.Printf("[deploy] Waiting... (%d/%d secrets, %ds/%ds)\n", found, len(cfg.Secrets), elapsed+3, maxWait)
	}

	if !allFound {
		ac.resetParameter(ctx, cfg.ssmParam("MigrationKMSKeyID"))
		return fmt.Errorf("timed out waiting for migration ciphertexts")
	}

	// Step 6: Copy each migration ciphertext to its permanent location.
	for _, secret := range cfg.Secrets {
		migCipher, _ := ac.getParameter(ctx, cfg.ssmParam("Migration/"+secret.Name+"/Ciphertext"))
		if err := ac.putParameter(ctx, cfg.ssmParam(secret.Name+"/Ciphertext"), migCipher); err != nil {
			return fmt.Errorf("copy migration ciphertext for %s: %w", secret.Name, err)
		}
	}
	fmt.Printf("[deploy] Copied %d migration ciphertexts to permanent locations\n", len(cfg.Secrets))

	// Step 7: Update KMSKeyID to the new key.
	if err := ac.putParameter(ctx, cfg.ssmParam("KMSKeyID"), newKMSKeyID); err != nil {
		return fmt.Errorf("update KMSKeyID: %w", err)
	}
	fmt.Printf("[deploy] Updated KMSKeyID to %s\n", newKMSKeyID)

	// Step 8: Stop old enclave, update EIF, restart watchdog.
	if err := restartEnclaveOnHost(ctx, ac, cfg, instanceID, eifBucket); err != nil {
		return err
	}

	// Step 9: Clean up migration SSM params.
	ac.resetParameter(ctx, cfg.ssmParam("MigrationKMSKeyID"))
	for _, secret := range cfg.Secrets {
		ac.resetParameter(ctx, cfg.ssmParam("Migration/"+secret.Name+"/Ciphertext"))
	}

	fmt.Println()
	fmt.Println("[deploy] Migration complete.")
	fmt.Printf("  Instance ID:  %s\n", instanceID)
	fmt.Printf("  New KMS Key:  %s\n", newKMSKeyID)
	fmt.Printf("  Old KMS Key:  %s (scheduled for deletion by new enclave on boot)\n", kmsKeyID)
	fmt.Printf("  PCR0:         %s\n", pcr0)

	// Read elastic IP from SSM (stored during fresh deploy) for verification.
	elasticIP, _ := ac.getParameter(ctx, cfg.ssmParam("ElasticIP"))
	if elasticIP != "" {
		fmt.Printf("\n[deploy] Verifying upgrade (waiting up to 60s)...\n")
		if err := initialVerification(elasticIP, pcr0, 60); err != nil {
			fmt.Printf("[deploy] Warning: verification did not pass: %v\n", err)
			fmt.Println("[deploy] Try: enclave verify --wait 300")
		}
	}

	return nil
}

// restartEnclaveOnHost downloads the new EIF from S3, replaces the EIF on disk,
// and restarts the enclave via the management server's start/stop endpoints.
func restartEnclaveOnHost(ctx context.Context, ac *awsClients, cfg *Config, instanceID, eifBucket string) error {
	return ac.runOnHost(ctx, instanceID, "stop enclave, update EIF, restart enclave", []string{
		"set -e",
		fmt.Sprintf("aws s3 cp s3://%s/image.eif /tmp/new-enclave.eif --region %s", eifBucket, cfg.Region),
		"curl -sf -X POST http://localhost:8443/stop || true",
		"cp /tmp/new-enclave.eif /home/ec2-user/app/server/enclave.eif",
		"chown ec2-user:ec2-user /home/ec2-user/app/server/enclave.eif",
		"curl -sf -X POST http://localhost:8443/start",
	})
}

// --- KMS policy functions ---

// applyTransitionalKMSPolicy applies a transitional KMS key policy for locked-key
// migration. Grants Encrypt + self-apply permissions to the EC2 role (so the new
// enclave can call PutKeyPolicy to add PCR0-restricted Decrypt during Init), and
// admin to the account root.
// Intentionally omits Decrypt — only the new enclave can add that after proving its PCR0.
//
// The EC2 role needs PutKeyPolicy and GetKeyPolicy granted directly in the key
// policy because its IAM policy is scoped to the old CDK-managed key ARN.
func applyTransitionalKMSPolicy(ctx context.Context, ac *awsClients, keyID, ec2RoleARN, account string) error {
	fmt.Println("[deploy] Applying transitional KMS key policy (Encrypt + admin, no Decrypt)")

	accountRoot := fmt.Sprintf("arn:aws:iam::%s:root", account)

	policy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable encrypt and self-apply from enclave",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": [
        "kms:Encrypt",
        "kms:GetKeyPolicy",
        "kms:PutKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Enable key administration (no decrypt)",
      "Effect": "Allow",
      "Principal": {"AWS": %q},
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:EnableKeyRotation",
        "kms:DisableKeyRotation",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:Encrypt"
      ],
      "Resource": "*"
    }
  ]
}`, ec2RoleARN, accountRoot)

	return ac.putKeyPolicy(ctx, keyID, policy, false)
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
		return "", fmt.Errorf("enclave/artifacts/pcr.json not found. Run 'enclave build' first.")
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
