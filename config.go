package introspector_enclave

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const configFile = "enclave/enclave.yaml"

type Config struct {
	Name         string           `yaml:"name"`
	Version      string           `yaml:"version"`
	Region       string           `yaml:"region"`
	Account      string           `yaml:"account"`
	Prefix       string           `yaml:"prefix"`
	Profile      string           `yaml:"profile"`
	App          AppConfig        `yaml:"app"`
	Secrets      []SecretConfig   `yaml:"secrets"`
	SDK          SDKConfig        `yaml:"sdk"`
	InstanceType string           `yaml:"instance_type"`
	NixImage     string           `yaml:"nix_image"`
}

type AppConfig struct {
	Language       string            `yaml:"language"`
	Source         string            `yaml:"source"`
	NixOwner       string            `yaml:"nix_owner"`
	NixRepo        string            `yaml:"nix_repo"`
	NixRev         string            `yaml:"nix_rev"`
	NixHash        string            `yaml:"nix_hash"`
	NixVendorHash  string            `yaml:"nix_vendor_hash"`
	NixSubPackages []string          `yaml:"nix_sub_packages"`
	NixProjectFile string            `yaml:"nix_project_file"`
	BinaryName     string            `yaml:"binary_name"`
	Env            map[string]string `yaml:"env"`
}

// SecretConfig defines a secret managed by KMS inside the enclave.
// Each secret is stored as an encrypted ciphertext in SSM and decrypted
// at boot via KMS attestation. The decrypted value is passed to the
// upstream app as the specified environment variable.
type SecretConfig struct {
	Name   string `yaml:"name"`    // SSM parameter name component
	EnvVar string `yaml:"env_var"` // Env var passed to upstream app
}

// SDKConfig defines the SDK coordinates for the enclave supervisor binary.
// These are used by Nix to fetch and build the enclave-supervisor from source.
type SDKConfig struct {
	Rev        string `yaml:"rev"`         // SDK git commit SHA
	Hash       string `yaml:"hash"`        // Nix source hash (SRI format)
	VendorHash string `yaml:"vendor_hash"` // Go vendor hash (SRI format)
}

func loadConfig() (*Config, error) {
	root, err := findRepoRoot()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(root, configFile))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w\nRun 'enclave init' to create one.", configFile, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", configFile, err)
	}
	// Apply defaults.
	if cfg.Prefix == "" {
		cfg.Prefix = "dev"
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.InstanceType == "" {
		cfg.InstanceType = "m6i.xlarge"
	}
	if cfg.App.BinaryName == "" {
		cfg.App.BinaryName = cfg.Name
	}
	if cfg.App.Source == "" {
		cfg.App.Source = "nix"
	}
	if cfg.App.Language == "" {
		cfg.App.Language = "go"
	}
	// Validate required fields.
	if cfg.Region == "" {
		return nil, fmt.Errorf("%s: 'region' is required", configFile)
	}
	// Validate secrets.
	seen := make(map[string]bool)
	for i, s := range cfg.Secrets {
		if s.Name == "" {
			return nil, fmt.Errorf("%s: secrets[%d].name is required", configFile, i)
		}
		if s.EnvVar == "" {
			return nil, fmt.Errorf("%s: secrets[%d].env_var is required", configFile, i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("%s: duplicate secret name %q", configFile, s.Name)
		}
		seen[s.Name] = true
	}
	return &cfg, nil
}

// validateAccount checks that the AWS account ID is present. Only needed for
// commands that interact with AWS (deploy, destroy, status, lock).
func (c *Config) validateAccount() error {
	if c.Account == "" {
		return fmt.Errorf("%s: 'account' is required", configFile)
	}
	return nil
}

// validateSDK checks that SDK coordinates are present. Only needed for commands
// that build the EIF (build, deploy), not for status/verify/destroy/lock.
func (c *Config) validateSDK() error {
	if c.SDK.Rev == "" {
		return fmt.Errorf("%s: 'sdk.rev' is required (SDK commit SHA)", configFile)
	}
	if c.SDK.Hash == "" {
		return fmt.Errorf("%s: 'sdk.hash' is required (Nix source hash)", configFile)
	}
	if c.SDK.VendorHash == "" {
		return fmt.Errorf("%s: 'sdk.vendor_hash' is required (Go vendor hash)", configFile)
	}
	return nil
}

// configEnv returns environment variables derived from the config, suitable
// for passing to scripts.
func (c *Config) configEnv() []string {
	env := os.Environ()
	env = append(env,
		"CDK_DEPLOY_REGION="+c.Region,
		"CDK_DEPLOY_ACCOUNT="+c.Account,
		"CDK_PREFIX="+c.Prefix,
		"VERSION="+c.Version,
		"AWS_REGION="+c.Region,
	)
	if c.Profile != "" {
		env = append(env, "AWS_PROFILE="+c.Profile)
	}
	return env
}

// CDKOutputs represents the structure of cdk-outputs.json.
type CDKOutputs map[string]map[string]string

func loadCDKOutputs(root string) (CDKOutputs, error) {
	data, err := os.ReadFile(filepath.Join(root, "enclave", "cdk-outputs.json"))
	if err != nil {
		return nil, fmt.Errorf("cannot read enclave/cdk-outputs.json: %w\nRun 'enclave deploy' first.", err)
	}
	var outputs CDKOutputs
	if err := json.Unmarshal(data, &outputs); err != nil {
		return nil, fmt.Errorf("invalid cdk-outputs.json: %w", err)
	}
	return outputs, nil
}

// getOutput reads a value from CDK outputs, trying multiple key variants.
func (o CDKOutputs) getOutput(stackName string, keys ...string) string {
	stack, ok := o[stackName]
	if !ok {
		return ""
	}
	for _, key := range keys {
		if v, ok := stack[key]; ok && v != "" {
			return v
		}
	}
	return ""
}

// stackName returns the CDK stack name from the config.
func (c *Config) stackName() string {
	return c.Prefix + "Nitro" + c.Name
}

// findRepoRoot walks up from cwd looking for enclave.yaml or .git.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, configFile)); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fall back to cwd.
	cwd, _ := os.Getwd()
	return cwd, nil
}
