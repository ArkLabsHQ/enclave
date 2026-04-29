package runtime

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Low-level KMS encrypt + SSM read/write helpers shared by the static-secret
// flow (static_secret.go), the migration flow (migrate.go), and the encrypted
// storage layer (storage.go).

// encryptWithKMS encrypts plaintext using KMS and returns base64-encoded ciphertext.
func encryptWithKMS(ctx context.Context, kmsClient *kms.Client, keyID string, plaintext []byte) (string, error) {
	out, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: plaintext,
	})
	if err != nil {
		return "", fmt.Errorf("kms encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(out.CiphertextBlob), nil
}

// storeCiphertextInSSM stores the base64-encoded ciphertext in SSM Parameter Store.
func storeCiphertextInSSM(ctx context.Context, ssmClient *ssm.Client, paramName, ciphertext string) error {
	_, err := ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(paramName),
		Value:     aws.String(ciphertext),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("ssm put-parameter %s: %w", paramName, err)
	}
	return nil
}

// loadCiphertextFromSSM attempts to load the ciphertext from SSM. Returns empty string if not found.
func loadCiphertextFromSSM(ctx context.Context, ssmClient *ssm.Client, paramName string) (string, error) {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		var pnf *ssmtypes.ParameterNotFound
		if errors.As(err, &pnf) {
			return "", nil
		}
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", nil
	}
	value := strings.TrimSpace(*out.Parameter.Value)
	if value == "" || value == "UNSET" {
		return "", nil
	}
	return value, nil
}

// getSecretSSMParamNameWithPrefix returns the SSM parameter name for a secret's
// ciphertext. Pass "" for primary storage, "Migration/" for migration staging.
func getSecretSSMParamNameWithPrefix(secretName, prefix string) string {
	deployment := getDeployment()
	appName := getAppName()
	return fmt.Sprintf("/%s/%s/%s%s/Ciphertext", deployment, appName, prefix, secretName)
}

// getKMSKeyID returns the KMS key ID from environment or SSM.
func getKMSKeyID(ctx context.Context, ssmClient *ssm.Client) (string, error) {
	deployment := getDeployment()
	appName := getAppName()
	paramName := fmt.Sprintf("/%s/%s/KMSKeyID", deployment, appName)
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(paramName),
		WithDecryption: aws.Bool(false),
	})
	if err != nil {
		return "", fmt.Errorf("ssm get-parameter %s: %w", paramName, err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil {
		return "", fmt.Errorf("KMS key ID not found in SSM parameter %s", paramName)
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "" || v == "UNSET" {
		return "", fmt.Errorf("KMS key ID not set in SSM parameter %s (value: %q)", paramName, v)
	}
	return v, nil
}

