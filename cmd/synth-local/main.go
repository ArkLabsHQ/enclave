// synth-local synthesizes the CDK stack with Local=true for deployment to
// localstack via cdklocal. S3 assets are included (stub files created for any
// missing artifacts); VPC/EC2/ECR are skipped.
//
// Usage:
//
//	go run ./cmd/synth-local                              # reads ./enclave/enclave.yaml
//	go run ./cmd/synth-local -config test/app/enclave/enclave.yaml -outdir test/cdk.out
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	introspector_enclave "github.com/ArkLabsHQ/introspector-enclave"
	"github.com/aws/aws-cdk-go/awscdk/v2"
	"github.com/aws/jsii-runtime-go"
	"gopkg.in/yaml.v3"
)

// assetStubs are files that CDK S3 assets reference. If they don't exist
// (e.g. no `enclave build` has been run), we create empty stubs so
// synthesis succeeds. The actual content doesn't matter for localstack.
var assetStubs = []string{
	"enclave/artifacts/image.eif",
	"enclave/artifacts/enclave-mgmt",
	"enclave/scripts/enclave_init.sh",
	"enclave/systemd/enclave-watchdog.service",
	"enclave/systemd/enclave-imds-proxy.service",
	"enclave/systemd/gvproxy.service",
	"enclave/systemd/enclave-mgmt.service",
}

func ensureStubs(repoRoot string) {
	for _, rel := range assetStubs {
		p := filepath.Join(repoRoot, rel)
		if _, err := os.Stat(p); err == nil {
			continue
		}
		os.MkdirAll(filepath.Dir(p), 0755)
		os.WriteFile(p, []byte("# stub for local CDK synthesis\n"), 0644)
		fmt.Printf("  Created stub: %s\n", rel)
	}
}

func main() {
	configPath := flag.String("config", "enclave/enclave.yaml", "path to enclave.yaml")
	outDir := flag.String("outdir", "", "CDK output directory (default: <config-dir>/cdk-local.out)")
	repoRoot := flag.String("repo", "", "repository root (default: parent of enclave/ in config path)")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	var cfg struct {
		Name    string `yaml:"name"`
		Region  string `yaml:"region"`
		Account string `yaml:"account"`
		Prefix  string `yaml:"prefix"`
		Secrets []struct {
			Name   string `yaml:"name"`
			EnvVar string `yaml:"env_var"`
		} `yaml:"secrets"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	if cfg.Prefix == "" {
		cfg.Prefix = "dev"
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	// Always use localstack's default account — the real account from
	// enclave.yaml is not relevant for local testing.
	cfg.Account = "000000000000"

	// Resolve repo root: explicit flag, or walk up from config path to find
	// the directory containing enclave/.
	root := *repoRoot
	if root == "" {
		// Config is at <root>/enclave/enclave.yaml or <root>/test/app/enclave/enclave.yaml.
		// Walk up from config dir looking for go.mod (repo root marker).
		dir, _ := filepath.Abs(filepath.Dir(*configPath))
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				root = dir
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
		if root == "" {
			root, _ = os.Getwd()
		}
	}

	// Create stub files for any missing S3 assets.
	ensureStubs(root)

	out := *outDir
	if out == "" {
		out = filepath.Join(filepath.Dir(*configPath), "cdk-local.out")
	}

	var secrets []introspector_enclave.SecretConfig
	for _, s := range cfg.Secrets {
		secrets = append(secrets, introspector_enclave.SecretConfig{
			Name:   s.Name,
			EnvVar: s.EnvVar,
		})
	}

	stackName := cfg.Prefix + "Nitro" + cfg.Name

	azKey := fmt.Sprintf("availability-zones:account=%s:region=%s", cfg.Account, cfg.Region)
	app := awscdk.NewApp(&awscdk.AppProps{
		Outdir: jsii.String(out),
		Context: &map[string]interface{}{
			azKey: []string{cfg.Region + "a", cfg.Region + "b"},
		},
	})

	introspector_enclave.NewNitroIntrospectorStack(app, stackName, &introspector_enclave.NitroIntrospectorStackProps{
		StackProps: awscdk.StackProps{
			Env: &awscdk.Environment{
				Account: jsii.String(cfg.Account),
				Region:  jsii.String(cfg.Region),
			},
		},
		Deployment: cfg.Prefix,
		RepoRoot:   root,
		AppName:    cfg.Name,
		Secrets:    secrets,
		Local:      true,
	})

	app.Synth(nil)

	// Print the outputs path for the deploy script.
	templateGlob := filepath.Join(out, "*.template.json")
	matches, _ := filepath.Glob(templateGlob)
	if len(matches) > 0 {
		fmt.Printf("Synthesized local stack %s to %s\n", stackName, out)
		fmt.Printf("Template: %s\n", matches[0])

		// Also write a small manifest for the deploy script.
		manifest := map[string]string{
			"stack_name": stackName,
			"out_dir":    out,
			"template":   matches[0],
		}
		manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
		manifestPath := filepath.Join(out, "local-manifest.json")
		os.WriteFile(manifestPath, manifestJSON, 0644)
	}
}
