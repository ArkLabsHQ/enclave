package introspector_enclave

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Execute runs the root cobra command. Called from cmd/enclave/main.go.
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
		buildCmd(),
		deployCmd(),
		startCmd(),
		stopCmd(),
		verifyCmd(),
		statusCmd(),
		curlCmd(),
		destroyCmd(),
		generateCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
