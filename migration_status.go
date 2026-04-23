package introspector_enclave

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
		Long: "Reads all migration SSM params and reports the current migration phase.\n" +
			"Useful for diagnosing a stuck migration or verifying state before/after a retry.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMigrationStatus(cmd.Context(), asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output raw JSON")
	return cmd
}

type migrationStatusReport struct {
	Deployment              string `json:"deployment"`
	AppName                 string `json:"app_name"`
	KMSKeyID                string `json:"kms_key_id,omitempty"`
	KMSKeyState             string `json:"kms_key_state,omitempty"`
	MigrationKMSKeyID       string `json:"migration_kms_key_id,omitempty"`
	MigrationKMSKeyState    string `json:"migration_kms_key_state,omitempty"`
	MigrationOldKMSKeyID    string `json:"migration_old_kms_key_id,omitempty"`
	MigrationPreviousPCR0   string `json:"migration_previous_pcr0,omitempty"`
	MigrationInProgress     bool   `json:"migration_in_progress"`
	Phase                   string `json:"phase"`
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

	deployment := cfg.Prefix
	if deployment == "" {
		deployment = "dev"
	}
	appName := cfg.Name

	report := migrationStatusReport{
		Deployment: deployment,
		AppName:    appName,
	}

	report.KMSKeyID = readSSMParamSilent(ctx, ac.ssmClient, deployment, appName, "KMSKeyID")
	report.MigrationKMSKeyID = readSSMParamSilent(ctx, ac.ssmClient, deployment, appName, "MigrationKMSKeyID")
	report.MigrationOldKMSKeyID = readSSMParamSilent(ctx, ac.ssmClient, deployment, appName, "MigrationOldKMSKeyID")
	report.MigrationPreviousPCR0 = readSSMParamSilent(ctx, ac.ssmClient, deployment, appName, "MigrationPreviousPCR0")

	report.MigrationInProgress = report.MigrationKMSKeyID != ""

	switch {
	case report.MigrationInProgress:
		report.Phase = "in-progress (MigrationKMSKeyID is set — new enclave may be mid-promotion or crashed)"
	case report.KMSKeyID == "":
		report.Phase = "uninitialized (no KMSKeyID in SSM)"
	default:
		report.Phase = "committed (no migration active)"
	}

	if report.KMSKeyID != "" {
		report.KMSKeyState = describeKMSKey(ctx, ac.kmsClient, report.KMSKeyID)
	}
	if report.MigrationKMSKeyID != "" {
		report.MigrationKMSKeyState = describeKMSKey(ctx, ac.kmsClient, report.MigrationKMSKeyID)
	}

	if asJSON {
		return json.NewEncoder(nopStdout{}).Encode(report)
	}

	fmt.Printf("Deployment:  %s/%s\n", report.Deployment, report.AppName)
	fmt.Printf("Phase:       %s\n", report.Phase)
	fmt.Println()
	fmt.Println("KMS keys:")
	fmt.Printf("  KMSKeyID                = %s (%s)\n", orUnset(report.KMSKeyID), orUnset(report.KMSKeyState))
	fmt.Printf("  MigrationKMSKeyID       = %s (%s)\n", orUnset(report.MigrationKMSKeyID), orUnset(report.MigrationKMSKeyState))
	fmt.Printf("  MigrationOldKMSKeyID    = %s\n", orUnset(report.MigrationOldKMSKeyID))
	fmt.Println()
	fmt.Println("Migration chain:")
	fmt.Printf("  MigrationPreviousPCR0   = %s\n", orUnset(report.MigrationPreviousPCR0))

	if report.MigrationInProgress {
		fmt.Println()
		fmt.Println("HINT: MigrationKMSKeyID is set. Either the new enclave is mid-promotion,")
		fmt.Println("      or a prior migration attempt failed. Check the enclave via 'enclave status'.")
		fmt.Println("      To recover, run 'enclave recover' after confirming the enclave is unresponsive.")
	}

	return nil
}

// readSSMParamSilent returns the raw value or empty string on any error.
// Treats "UNSET" as empty.
func readSSMParamSilent(ctx context.Context, ssmClient *ssm.Client, deployment, appName, name string) string {
	paramName := fmt.Sprintf("/%s/%s/%s", deployment, appName, name)
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
