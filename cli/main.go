package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Execute builds the root cobra command and runs it. Called from cli/cmd/main.go.
func Execute() {
	rootCmd := &cobra.Command{
		Use:     "enclave",
		Short:   "Nitro Enclave deployment CLI",
		Long:    "Build, deploy, and manage applications inside AWS Nitro Enclaves.",
		Version: Version,
	}

	rootCmd.AddCommand(
		initCmd(),
		setupCmd(),
		updateCmd(),
		upgradeCmd(),
		tofuCmd(),
		buildCmd(),
		startCmd(),
		stopCmd(),
		verifyCmd(),
		statusCmd(),
		curlCmd(),
		generateCmd(),
		logCmd(),
		traceCmd(),
		metricsCmd(),
		migrationStatusCmd(),
		testCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
