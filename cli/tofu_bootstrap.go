package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// bootstrapBackend runs `tofu init` + `tofu apply -auto-approve` on the
// backend sub-module to create the S3 state bucket + DynamoDB lock table.
// Stdio is inherited so the operator sees tofu's progress live.
func bootstrapBackend(root string, o *backendOverride) error {
	backendDir := filepath.Join(root, "tofu", "modules", "backend")
	if _, err := os.Stat(filepath.Join(backendDir, "main.tf")); err != nil {
		return fmt.Errorf("backend module not found at %s: %w", backendDir, err)
	}
	if _, err := exec.LookPath("tofu"); err != nil {
		return fmt.Errorf("tofu binary not on PATH (install: https://opentofu.org/docs/intro/install/): %w", err)
	}
	if o == nil {
		return fmt.Errorf("bootstrap: nil backend override")
	}

	fmt.Println("Downloading providers (first run may take a minute)...")
	initCmd := exec.Command("tofu", "-chdir="+backendDir, "init", "-input=false")
	initCmd.Stdin, initCmd.Stdout, initCmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := initCmd.Run(); err != nil {
		return fmt.Errorf("tofu init (backend): %w", err)
	}

	fmt.Println("\nApplying backend module (creates S3 state bucket + DynamoDB lock table)...")
	applyCmd := exec.Command("tofu", "-chdir="+backendDir, "apply", "-auto-approve", "-input=false",
		"-var", "bucket_name="+o.bucket,
		"-var", "table_name="+o.table,
		"-var", "region="+o.region,
	)
	applyCmd.Stdin, applyCmd.Stdout, applyCmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := applyCmd.Run(); err != nil {
		return fmt.Errorf("tofu apply (backend): %w\n\nIf the error mentions BucketAlreadyExists, the bucket name is taken — pick a different name or import the existing one with:\n  tofu -chdir=%s import aws_s3_bucket.state %s", err, backendDir, o.bucket)
	}
	return nil
}
