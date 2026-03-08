package introspector_enclave

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/jsii-runtime-go"
)

// runCmd runs an external command with the given environment, streaming
// stdout/stderr to the terminal. Returns an error if the command fails.
func runCmd(name string, args []string, dir string, env []string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

// synthCDKStack synthesizes the CDK stack to cdk.out/ by calling
// NewNitroIntrospectorStack directly. No external cdk.json or app command needed.
func synthCDKStack(cfg *Config, root string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repo root: %w", err)
	}

	outDir := filepath.Join(absRoot, "enclave", "cdk.out")

	// Provide AZ context so CDK doesn't fall back to dummy AZs.
	// The Go synth has no context provider, so we supply AZs explicitly.
	azContextKey := fmt.Sprintf("availability-zones:account=%s:region=%s", cfg.Account, cfg.Region)
	az1 := cfg.Region + "a"
	az2 := cfg.Region + "b"

	app := awscdk.NewApp(&awscdk.AppProps{
		Outdir: jsii.String(outDir),
		Context: &map[string]interface{}{
			azContextKey: []string{az1, az2},
		},
	})

	NewNitroIntrospectorStack(app, cfg.stackName(), &NitroIntrospectorStackProps{
		StackProps: awscdk.StackProps{
			Env: &awscdk.Environment{
				Account: jsii.String(cfg.Account),
				Region:  jsii.String(cfg.Region),
			},
		},
		Deployment:   cfg.Prefix,
		RepoRoot:     absRoot,
		InstanceType: cfg.InstanceType,
		AppName:      cfg.Name,
		Secrets:      cfg.Secrets,
	})

	app.Synth(nil)
	fmt.Printf("[cdk] Synthesized stack %s to %s\n", cfg.stackName(), outDir)
	return nil
}

// runCDKDeploy synthesizes the CDK stack and deploys it via the cdk CLI.
// The stack is synthesized inline (no cdk.json needed), then deployed
// from the pre-synthesized cdk.out/ directory.
func runCDKDeploy(cfg *Config, root string) error {
	if err := synthCDKStack(cfg, root); err != nil {
		return err
	}

	outputsPath := filepath.Join(root, "enclave", "cdk-outputs.json")
	env := cfg.configEnv()

	return runCmd("cdk", []string{
		"deploy",
		"--app", filepath.Join(root, "enclave", "cdk.out"),
		"--require-approval", "never",
		"-O", outputsPath,
	}, root, env)
}
