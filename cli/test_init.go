package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func testCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run the app inside a local QEMU enclave for integration testing",
		Long: `Boot the upstream app's EIF inside an emulated Nitro Enclave on
localhost:8443, with mock AWS services (KMS, SSM, S3, IMDS) wired in.

Workflow:

  enclave test build   Build the test EIF from enclave_test.yaml.

  enclave test init    Scaffold enclave/test/docker-compose.yml.
                       Hand-edit it to add app-specific mock services
                       (e.g. mock-arkd) below the user-services marker.

  enclave test start   docker compose up -d --build the whole stack
                       and wait for /health to return 200.

  enclave test down    Tear the stack down + remove volumes.`,
	}
	cmd.AddCommand(testBuildCmd(), testInitCmd(), testStartCmd(), testDownCmd())
	return cmd
}

func testBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the test EIF from enclave_test.yaml (auto-discovered)",
		RunE:  runTestBuild,
	}
	cmd.Flags().StringP("config", "c", "", "path to enclave.yaml (defaults to enclave/enclave_test.yaml, then enclave/enclave.yaml). Same auto-discovery as `enclave test init` / `start`.")
	return cmd
}

func runTestBuild(cmd *cobra.Command, _ []string) error {
	configPath, _ := cmd.Flags().GetString("config")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	cfg, picked, err := loadTestConfig(cwd, configPath)
	if err != nil {
		return err
	}
	fmt.Printf("Using %s\n", picked)

	return runBuildWithConfig(cfg)
}

func testInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold enclave/test/docker-compose.yml from enclave.yaml",
		RunE:  runTestInit,
	}
	cmd.Flags().Bool("force-compose", false, "regenerate enclave/test/docker-compose.yml even if it exists (clobbers hand-edits)")
	cmd.Flags().StringP("config", "c", "", "path to enclave.yaml (defaults to enclave/enclave.yaml). Use to point at a test-only variant, e.g. enclave/enclave_test.yaml.")
	return cmd
}

func testStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Boot the test stack and wait for the enclave to report ready",
		RunE:  runTestStart,
	}
	cmd.Flags().StringP("config", "c", "", "path to enclave.yaml the EIF was built from (defaults to enclave/enclave.yaml). Used only for compose-project naming; the compose file itself must already exist (run `enclave test init` first).")
	return cmd
}

func testDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Tear down the running test stack",
		RunE:  runTestDown,
	}
}

func runTestInit(cmd *cobra.Command, _ []string) error {
	force, _ := cmd.Flags().GetBool("force-compose")
	configPath, _ := cmd.Flags().GetString("config")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	cfg, picked, err := loadTestConfig(cwd, configPath)
	if err != nil {
		return err
	}
	fmt.Printf("Using %s\n", picked)

	written, err := writeTestCompose(cfg, cwd, force)
	if err != nil {
		return err
	}
	if written {
		fmt.Printf("Wrote %s\n", composeFilePath)
		fmt.Println("Hand-edit the file to add app-specific services below the user-services marker, then run `enclave test start`.")
	} else {
		fmt.Printf("Using existing %s (use --force-compose to regenerate)\n", composeFilePath)
	}
	return nil
}

func runTestStart(cmd *cobra.Command, _ []string) error {
	configPath, _ := cmd.Flags().GetString("config")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	_, picked, err := loadTestConfig(cwd, configPath)
	if err != nil {
		return err
	}
	fmt.Printf("Using %s\n", picked)

	if _, err := os.Stat(filepath.Join(cwd, composeFilePath)); err != nil {
		return fmt.Errorf("compose file %s missing — run `enclave test init` first", composeFilePath)
	}

	eifPath := filepath.Join(cwd, ".enclave", "artifacts", "image.eif")
	if _, err := os.Stat(eifPath); err != nil {
		return fmt.Errorf("EIF not found at %s — run `enclave build` first", eifPath)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := bootTestStack(ctx, cwd); err != nil {
		return err
	}

	printConnectionInfo(cwd)
	return nil
}

func runTestDown(cmd *cobra.Command, _ []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return tearDownTestStack(ctx, cwd)
}

// loadTestConfig resolves a *Config from (in order): the override
// path, ENCLAVE_CONFIG, then enclave_test.yaml before enclave.yaml in
// both ./ and ./enclave/. Test variants win so `enclave test {init,
// start}` works without --config.
func loadTestConfig(projectRoot, override string) (*Config, string, error) {
	cfgPath := override
	if cfgPath == "" {
		cfgPath = os.Getenv("ENCLAVE_CONFIG")
	}
	if cfgPath != "" && !filepath.IsAbs(cfgPath) {
		cfgPath = filepath.Join(projectRoot, cfgPath)
	}
	if cfgPath == "" {
		candidates := []string{
			filepath.Join(projectRoot, "enclave", "enclave_test.yaml"),
			filepath.Join(projectRoot, "enclave_test.yaml"),
			filepath.Join(projectRoot, "enclave", "enclave.yaml"),
			filepath.Join(projectRoot, "enclave.yaml"),
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				cfgPath = p
				break
			}
		}
		if cfgPath == "" {
			return nil, "", fmt.Errorf("no enclave.yaml or enclave_test.yaml found under %s", projectRoot)
		}
	}
	cfg, err := loadConfigAt(cfgPath)
	if err != nil {
		return nil, cfgPath, err
	}
	return cfg, cfgPath, nil
}

func printConnectionInfo(projectRoot string) {
	pcrPath := filepath.Join(projectRoot, ".enclave", "artifacts", "pcr.json")
	pcr0 := "<unknown — pcr.json missing>"
	if data, err := os.ReadFile(pcrPath); err == nil {
		var p struct {
			PCR0 string `json:"PCR0"`
		}
		if json.Unmarshal(data, &p) == nil && p.PCR0 != "" {
			pcr0 = p.PCR0
		}
	}
	fmt.Println()
	fmt.Println("Enclave running.")
	fmt.Println("  URL:     https://localhost:8443")
	fmt.Println("  PCR0:    " + pcr0)
	fmt.Println("  Compose: " + composeFilePath)
	fmt.Println("  Stop:    enclave test down")
}
