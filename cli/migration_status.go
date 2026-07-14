package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/spf13/cobra"
)

func migrationStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "migration-status",
		Short: "Show migration-related SSM state and KMS key status",
		Long: "Reads the KMS key ID, key state, and previous-PCR0 migration chain from SSM.\n" +
			"Useful for verifying state before or after a migration.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMigrationStatus(cmd.Context(), asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON")
	return cmd
}

type migrationStatusReport struct {
	Deployment            string `json:"deployment"`
	AppName               string `json:"app_name"`
	KMSKeyID              string `json:"kms_key_id,omitempty"`
	KMSKeyState           string `json:"kms_key_state,omitempty"`
	MigrationPreviousPCR0 string `json:"migration_previous_pcr0,omitempty"`
}

func runMigrationStatus(ctx context.Context, asJSON bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ac, err := newAWSClients(ctx, cfg.Region, cfg.Profile)
	if err != nil {
		return err
	}

	deployment := cfg.Deployment
	if deployment == "" {
		deployment = "dev"
	}
	appName := cfg.Name

	report := migrationStatusReport{
		Deployment: deployment,
		AppName:    appName,
	}

	lockSegment := "unlocked"
	if cfg.IsKMSKeyLocked {
		lockSegment = "locked"
	}

	report.KMSKeyID = readSSMParamSilent(ctx, ac.ssmClient, fmt.Sprintf("/%s/%s/%s/KMSKeyID", deployment, appName, lockSegment))
	report.MigrationPreviousPCR0 = readSSMParamSilent(ctx, ac.ssmClient, fmt.Sprintf("/%s/%s/MigrationPreviousPCR0", deployment, appName))

	if report.KMSKeyID != "" {
		report.KMSKeyState = describeKMSKey(ctx, ac.kmsClient, report.KMSKeyID)
	}

	if asJSON {
		return json.NewEncoder(nopStdout{}).Encode(report)
	}

	fmt.Printf("Deployment:  %s/%s\n", report.Deployment, report.AppName)
	fmt.Println()
	fmt.Println("KMS keys:")
	fmt.Printf("  KMSKeyID                = %s (%s)\n", orUnset(report.KMSKeyID), orUnset(report.KMSKeyState))
	fmt.Println()
	fmt.Println("Migration chain:")
	fmt.Printf("  MigrationPreviousPCR0   = %s\n", orUnset(report.MigrationPreviousPCR0))

	return nil
}

// readSSMParamSilent returns the raw value or empty string on any error.
// Treats "UNSET" as empty.
func readSSMParamSilent(ctx context.Context, ssmClient *ssm.Client, paramName string) string {
	out, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(paramName),
	})
	if err != nil || out.Parameter == nil || out.Parameter.Value == nil {
		return ""
	}
	v := strings.TrimSpace(*out.Parameter.Value)
	if v == "UNSET" {
		return ""
	}
	return v
}

// describeKMSKey returns a short state string (enabled, pending-deletion, etc.).
func describeKMSKey(ctx context.Context, kmsClient *kms.Client, keyID string) string {
	out, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return "unknown: " + err.Error()
	}
	if out.KeyMetadata == nil {
		return "no-metadata"
	}
	return string(out.KeyMetadata.KeyState)
}

func orUnset(s string) string {
	if s == "" {
		return "<unset>"
	}
	return s
}

type nopStdout struct{}

func (nopStdout) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
