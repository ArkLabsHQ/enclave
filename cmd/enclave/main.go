package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set by the Nix package build.
var Version = "dev"

// Execute runs the enclave command-line client.
func Execute() {
	root := NewRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}

// NewRootCommand creates the root command.  It is exported so the command
// surface can be tested without exiting the process.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:     "enclave",
		Short:   "Verified client for AWS Nitro Enclaves",
		Long:    "Make attestation-verified requests to an AWS Nitro Enclave.",
		Version: Version,
	}
	root.AddCommand(newCurlCommand())
	return root
}
