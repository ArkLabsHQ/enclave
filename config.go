package introspector_enclave

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	accountIDRegex  = regexp.MustCompile(`^\d{12}$`)
	secretNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	envVarRegex     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// reservedEnvPrefixes lists env var prefixes that must not be used for secrets.
var reservedEnvPrefixes = []string{"ENCLAVE_", "AWS_"}

const configFile = "enclave/enclave.yaml"

type Config struct {
	Name         string         `yaml:"name"`
	Version      string         `yaml:"version"`
	Region       string         `yaml:"region"`
	Account      string         `yaml:"account"`
	Prefix       string         `yaml:"prefix"`
	Profile      string         `yaml:"profile"`
	App          AppConfig      `yaml:"app"`
	Secrets      []SecretConfig `yaml:"secrets"`
	SDK          SDKConfig      `yaml:"sdk"`
	InstanceType      string         `yaml:"instance_type"`
	NixImage          string         `yaml:"nix_image"`
	MigrationCooldown string         `yaml:"migration_cooldown"`
	PreviousPCR0      string         `yaml:"previous_pcr0"`
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
	// ENCLAVE_CONFIG overrides the default config path (useful for local testing
	// with a config at a non-standard location like test/app/enclave/enclave.yaml).
	configPath := os.Getenv("ENCLAVE_CONFIG")
	if configPath == "" {
		root, err := findRepoRoot()
		if err != nil {
			return nil, err
		}
		configPath = filepath.Join(root, configFile)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w (run 'enclave init' to create one)", configPath, err)
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
	if cfg.MigrationCooldown == "" {
		cfg.MigrationCooldown = "0s"
	}
	if _, err := time.ParseDuration(cfg.MigrationCooldown); err != nil {
		return nil, fmt.Errorf("%s: invalid migration_cooldown %q: %w", configFile, cfg.MigrationCooldown, err)
	}
	if cfg.PreviousPCR0 == "" {
		cfg.PreviousPCR0 = "genesis"
	}
	// Validate required fields.
	if cfg.Name == "" {
		return nil, fmt.Errorf("%s: 'name' is required", configFile)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("%s: 'region' is required", configFile)
	}

	// Validate secrets.
	seen := make(map[string]bool)
	seenEnv := make(map[string]bool)
	for i, s := range cfg.Secrets {
		if s.Name == "" {
			return nil, fmt.Errorf("%s: secrets[%d].name is required", configFile, i)
		}
		if s.EnvVar == "" {
			return nil, fmt.Errorf("%s: secrets[%d].env_var is required", configFile, i)
		}
		if !secretNameRegex.MatchString(s.Name) {
			return nil, fmt.Errorf("%s: secrets[%d].name %q must be alphanumeric with underscores, starting with a letter", configFile, i, s.Name)
		}
		if !envVarRegex.MatchString(s.EnvVar) {
			return nil, fmt.Errorf("%s: secrets[%d].env_var %q must be uppercase alphanumeric with underscores", configFile, i, s.EnvVar)
		}
		for _, prefix := range reservedEnvPrefixes {
			if len(s.EnvVar) >= len(prefix) && s.EnvVar[:len(prefix)] == prefix {
				return nil, fmt.Errorf("%s: secrets[%d].env_var %q uses reserved prefix %q", configFile, i, s.EnvVar, prefix)
			}
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("%s: duplicate secret name %q", configFile, s.Name)
		}
		if seenEnv[s.EnvVar] {
			return nil, fmt.Errorf("%s: duplicate secret env_var %q", configFile, s.EnvVar)
		}
		seen[s.Name] = true
		seenEnv[s.EnvVar] = true
	}
	return &cfg, nil
}

// validateAccount checks that the AWS account ID is present and valid.
// Only needed for commands that interact with AWS (deploy, destroy, status, lock).
func (c *Config) validateAccount() error {
	if c.Account == "" {
		return fmt.Errorf("%s: 'account' is required", configFile)
	}
	if !accountIDRegex.MatchString(c.Account) {
		return fmt.Errorf("%s: account %q must be a 12-digit AWS account ID", configFile, c.Account)
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
		return nil, fmt.Errorf("cannot read enclave/cdk-outputs.json: %w (run 'enclave deploy' first)", err)
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

// findAppRoot returns the root directory of the app (parent of enclave/).
// When ENCLAVE_CONFIG is set, derives it from the config path (go up 2 levels
// from .../enclave/enclave.yaml). Otherwise falls back to findRepoRoot().
func findAppRoot() (string, error) {
	if configPath := os.Getenv("ENCLAVE_CONFIG"); configPath != "" {
		abs, err := filepath.Abs(configPath)
		if err != nil {
			return "", err
		}
		// configPath = .../enclave/enclave.yaml → go up 2 levels
		return filepath.Dir(filepath.Dir(abs)), nil
	}
	return findRepoRoot()
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
