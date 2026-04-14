package sdk

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hf/nsm"
)

// handleExportKey handles POST /v1/export-key.
// Exports all configured secrets encrypted with a temporary migration KMS key.
// Authorization: the endpoint only operates when MigrationKMSKeyID is set in SSM
// (written by the CLI before calling this endpoint). The exported ciphertexts are
// encrypted to the new KMS key, which only the new enclave can decrypt.
func (e *Enclave) handleExportKey(w http.ResponseWriter, r *http.Request) {
	if !e.initDone.Load() {
		http.Error(w, "enclave is still initializing", http.StatusServiceUnavailable)
		return
	}

	// Parse request body — caller provides the migration key ID and the new
	// enclave's PCR0 (used to lock the migration key's Decrypt policy before
	// any ciphertext is produced).
	var req struct {
		MigrationKeyID string `json:"migration_key_id"`
		NewPCR0        string `json:"new_pcr0"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MigrationKeyID == "" || req.NewPCR0 == "" {
		http.Error(w, "migration_key_id and new_pcr0 are required in request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	deployment := getDeployment()
	appName := getAppName()

	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ssmClient := newSSMClient(awsCfg)

	// Verify the provided migration key ID matches what's stored in SSM.
	// This ensures the caller is the same entity that initiated the migration.
	migrationKeyID, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationKMSKeyID", deployment, appName))
	if err != nil {
		http.Error(w, "migration key not configured", http.StatusPreconditionFailed)
		return
	}
	if migrationKeyID != req.MigrationKeyID {
		http.Error(w, "migration_key_id does not match", http.StatusForbidden)
		return
	}

	kmsClient := newKMSClient(awsCfg)

	// Lock the migration key to the new enclave's PCR0 BEFORE encrypting under
	// it. The mgmt server created this key with a bootstrap policy that grants
	// only kms:PutKeyPolicy / kms:GetKeyPolicy / kms:ScheduleKeyDeletion to the
	// EC2 role; installing the final locked policy here ensures that once a
	// ciphertext exists, no principal can mutate the policy to grant itself
	// Decrypt. Idempotent: if a previous attempt already locked the policy to
	// this PCR0 we skip PutKeyPolicy (which would fail — the locked policy
	// grants PutKeyPolicy to no one) and fall through to re-encrypt.
	currentPolicy, err := kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(migrationKeyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("get migration key policy: %v", err), http.StatusInternalServerError)
		return
	}
	currentPolicyText := ""
	if currentPolicy.Policy != nil {
		currentPolicyText = *currentPolicy.Policy
	}
	alreadyLocked, _ := parseKMSPolicyState(currentPolicyText, req.NewPCR0)
	if alreadyLocked {
		slog.Info("migration key already locked to target PCR0, skipping PutKeyPolicy", "key_id", migrationKeyID, "new_pcr0", req.NewPCR0[:min(16, len(req.NewPCR0))])
	} else {
		stsClient := sts.NewFromConfig(awsCfg)
		identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			http.Error(w, fmt.Sprintf("sts get-caller-identity: %v", err), http.StatusInternalServerError)
			return
		}
		roleARN, err := assumedRoleARNToRoleARN(*identity.Arn)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve IAM role ARN: %v", err), http.StatusInternalServerError)
			return
		}
		lockedPolicy := buildKMSPolicy(roleARN, req.NewPCR0)
		if _, err := kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
			KeyId:                          aws.String(migrationKeyID),
			Policy:                         aws.String(lockedPolicy),
			PolicyName:                     aws.String("default"),
			BypassPolicyLockoutSafetyCheck: true,
		}); err != nil {
			http.Error(w, fmt.Sprintf("lock migration key policy: %v", err), http.StatusInternalServerError)
			return
		}
		slog.Info("applied PCR0-locked policy to migration key", "key_id", migrationKeyID, "new_pcr0", req.NewPCR0[:min(16, len(req.NewPCR0))])
	}

	var exported []string
	for _, secret := range e.secrets {
		secretValue := os.Getenv(secret.EnvVar)
		if secretValue == "" {
			continue
		}

		keyBytes, err := hex.DecodeString(secretValue)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid key format for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		ciphertextB64, err := encryptWithKMS(ctx, kmsClient, migrationKeyID, keyBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf("KMS encrypt failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		ciphertextParam := fmt.Sprintf("/%s/%s/Migration/%s/Ciphertext", deployment, appName, secret.Name)
		if err := storeCiphertextInSSM(ctx, ssmClient, ciphertextParam, ciphertextB64); err != nil {
			http.Error(w, fmt.Sprintf("SSM store failed for %s", secret.Name), http.StatusInternalServerError)
			return
		}

		exported = append(exported, secret.Name)
	}

	// Export storage DEK: re-encrypt under migration KMS key.
	if err := e.exportStorageDEK(ctx, kmsClient, ssmClient, migrationKeyID); err != nil {
		http.Error(w, fmt.Sprintf("storage DEK export failed: %v", err), http.StatusInternalServerError)
		return
	}

	pcr0, _, err := storePCR0WithAttestation(ctx, ssmClient, deployment, appName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		PCR0     string   `json:"pcr0"`
		Exported []string `json:"exported"`
	}{
		PCR0:     pcr0,
		Exported: exported,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// readMigrationPreviousPCR0 reads the previous enclave's PCR0 from SSM.
func readMigrationPreviousPCR0(ctx context.Context) (string, error) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return "", err
	}
	ssmClient := newSSMClient(awsCfg)
	deployment := getDeployment()
	appName := getAppName()
	return readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName))
}

// readMigrationPreviousPCR0Attestation reads the previous enclave's attestation
// document from SSM. Returns a base64-encoded COSE Sign1 structure.
func readMigrationPreviousPCR0Attestation(ctx context.Context) (string, error) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		return "", err
	}
	ssmClient := newSSMClient(awsCfg)
	deployment := getDeployment()
	appName := getAppName()
	return readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName))
}

// storePCR0WithAttestation stores both the plain PCR0 and a cryptographic
// attestation document in SSM. The attestation document is a COSE Sign1
// structure signed by AWS Nitro hardware, proving the PCR0 value.
func storePCR0WithAttestation(ctx context.Context, ssmClient *ssm.Client, deployment, appName string) (string, string, error) {
	pcr0 := getPCR0()
	if pcr0 == "" {
		return "", "", fmt.Errorf("could not read PCR0 from NSM")
	}

	pcr0Param := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName)
	_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(pcr0Param),
		Value:     aws.String(pcr0),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return "", "", fmt.Errorf("store PCR0 in SSM: %w", err)
	}

	attestDocB64, err := getAttestationDocumentB64()
	if err != nil {
		return "", "", fmt.Errorf("generate attestation document: %w", err)
	}

	attestParam := fmt.Sprintf("/%s/%s/MigrationPreviousPCR0Attestation", deployment, appName)
	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(attestParam),
		Value:     aws.String(attestDocB64),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
		Tier:      ssmtypes.ParameterTierAdvanced,
	})
	if err != nil {
		return "", "", fmt.Errorf("store PCR0 attestation in SSM: %w", err)
	}

	return pcr0, attestDocB64, nil
}



// deleteOldKMSKey checks if MigrationOldKMSKeyID is set in SSM. If so,
// schedules the old KMS key for deletion and clears the parameter.
func deleteOldKMSKey(ctx context.Context) {
	awsCfg, err := loadAWSConfigWithIMDS(ctx)
	if err != nil {
		slog.Warn("deleteOldKMSKey: load AWS config failed", "error", err)
		return
	}
	ssmClient := newSSMClient(awsCfg)
	deployment := getDeployment()
	appName := getAppName()

	oldKeyID, err := readSSMParam(ctx, ssmClient, fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName))
	if err != nil {
		return // no old key to delete — normal case
	}

	kmsClient := newKMSClient(awsCfg)
	pendingDays := int32(7)
	_, err = kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(oldKeyID),
		PendingWindowInDays: &pendingDays,
	})
	if err != nil {
		slog.Warn("deleteOldKMSKey: schedule deletion failed", "key_id", oldKeyID, "error", err)
		return
	}
	slog.Info("scheduled old KMS key for deletion", "key_id", oldKeyID, "pending_days", 7)

	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(fmt.Sprintf("/%s/%s/MigrationOldKMSKeyID", deployment, appName)),
		Value:     aws.String("UNSET"),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		slog.Warn("deleteOldKMSKey: clear SSM param failed", "error", err)
	}
}

// readSSMParam reads an SSM parameter value. Returns error if missing or UNSET.
func readSSMParam(ctx context.Context, ssmClient *ssm.Client, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("parameter %s has no value", paramName)
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", fmt.Errorf("parameter %s is unset", paramName)
	}
	return value, nil
}

// getDeployment returns the deployment prefix from environment.
func getDeployment() string {
	if d := strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT")); d != "" {
		return d
	}
	if d := strings.TrimSpace(os.Getenv("INTROSPECTOR_DEPLOYMENT")); d != "" {
		return d
	}
	return "dev"
}

// getAppName returns the app name from environment.
func getAppName() string {
	if name := strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME")); name != "" {
		return name
	}
	return "app"
}

// getPCR0 returns this enclave's PCR0 from the NSM attestation document.
func getPCR0() string {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return ""
	}
	defer func() { _ = session.Close() }()

	attestDoc, _, err := buildAttestationDocument(session)
	if err != nil {
		return ""
	}

	pcr0, err := extractPCR0FromAttestation(attestDoc)
	if err != nil {
		return ""
	}
	return pcr0
}
