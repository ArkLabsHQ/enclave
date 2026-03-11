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

// synthCDKStack synthesizes the CDK stack by calling NewNitroIntrospectorStack
// directly. No external cdk.json or app command needed.
//
// When LOCAL_DEPLOYMENT=true, synthesizes with Local=true (skips VPC/EC2/ECR)
// and outputs to cdk-local.out instead of cdk.out.
func synthCDKStack(cfg *Config, root string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repo root: %w", err)
	}

	outDir := filepath.Join(absRoot, "enclave", "cdk.out")
	local := os.Getenv("LOCAL_DEPLOYMENT") == "true"

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
		Local:        local,
	})

	app.Synth(nil)
	fmt.Printf("[cdk] Synthesized stack %s to %s\n", cfg.stackName(), outDir)
	return nil
}

// runCDKDeploy synthesizes the CDK stack and deploys it via the cdk CLI.
// The stack is synthesized inline (no cdk.json needed), then deployed
// from the pre-synthesized output directory.
//
// When LOCAL_DEPLOYMENT=true, uses cdklocal instead of cdk, runs bootstrap
// first (required by localstack), and writes outputs to test/cdk-local-outputs.json.
func runCDKDeploy(cfg *Config, root string) error {
	if err := synthCDKStack(cfg, root); err != nil {
		return err
	}

	local := os.Getenv("LOCAL_DEPLOYMENT") == "true"
	env := cfg.configEnv()

	cdkCmd := "cdk"
	if local {
		cdkCmd = findCDKLocal()

		// localstack requires bootstrapping.
		fmt.Println("[cdk] Bootstrapping CDK (localstack)...")
		if err := runCmd(cdkCmd, []string{
			"bootstrap",
			"--app", filepath.Join(root, "enclave", "cdk.out"),
			"aws://" + cfg.Account + "/" + cfg.Region,
		}, root, env); err != nil {
			return fmt.Errorf("cdklocal bootstrap: %w", err)
		}
	}

	return runCmd(cdkCmd, []string{
		"deploy",
		"--app", filepath.Join(root, "enclave", "cdk.out"),
		"--require-approval", "never",
		"-O", filepath.Join(root, "enclave", "cdk-outputs.json"),
	}, root, env)
}

// runCDKDestroy destroys the CDK stack. Uses cdklocal when LOCAL_DEPLOYMENT=true.
func runCDKDestroy(cfg *Config, root string) error {
	env := cfg.configEnv()

	cdkCmd := "cdk"
	if os.Getenv("LOCAL_DEPLOYMENT") == "true" {
		cdkCmd = findCDKLocal()
	}

	return runCmd(cdkCmd, []string{
		"destroy",
		"--app", filepath.Join(root, "enclave", "cdk.out"),
		"--force",
	}, root, env)
}

// findCDKLocal locates the cdklocal binary. Checks PATH first, then a common
// local install at /tmp/cdklocal, and falls back to installing it.
func findCDKLocal() string {
	if path, err := exec.LookPath("cdklocal"); err == nil {
		return path
	}
	localPath := "/tmp/cdklocal/node_modules/.bin/cdklocal"
	if _, err := os.Stat(localPath); err == nil {
		return localPath
	}
	fmt.Println("[cdk] cdklocal not found. Installing to /tmp/cdklocal...")
	cmd := exec.Command("npm", "install", "--prefix", "/tmp/cdklocal", "aws-cdk-local", "aws-cdk")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to install cdklocal: %v\n", err)
		return "cdklocal" // fall back, will fail with a clear error
	}
	return localPath
}
