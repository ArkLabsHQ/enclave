package cli

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	accountIDRegex  = regexp.MustCompile(`^\d{12}$`)
	secretNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	envVarRegex     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	fqdnRegex       = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	commitSHARegex  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	cachixHostRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.cachix\.org$`)
	publicKeyRegex  = regexp.MustCompile(`^[A-Za-z0-9._-]+:[A-Za-z0-9+/]+=*$`)
	// SRI sha256: "sha256-" + 43 base64 chars + "=" (32 raw bytes → 44 base64).
	sriSha256Regex = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)
)

// reservedEnvPrefixes lists env var prefixes that must not be used for secrets.
var reservedEnvPrefixes = []string{"ENCLAVE_", "AWS_"}

const (
	configFile     = "enclave/enclave.yaml" // canonical layout: enclave/ subdir at project root
	configFileBare = "enclave.yaml"         // alternate layout: enclave.yaml directly at project root
)

type Config struct {
	Name                     string         `yaml:"name"`
	Version                  string         `yaml:"version"`
	Region                   string         `yaml:"region"`
	Account                  string         `yaml:"account"`
	Deployment               string         `yaml:"deployment"`
	Profile                  string         `yaml:"profile"`
	App                      AppConfig      `yaml:"app"`
	Secrets                  []SecretConfig `yaml:"secrets"`
	Runtime                  RuntimeConfig  `yaml:"runtime"`
	InstanceType             string         `yaml:"instance_type"`
	MigrationCooldown        string         `yaml:"migration_cooldown"`
	MigrationIntentRetention string         `yaml:"migration_intent_retention"`
	PreviousPCR0             string         `yaml:"previous_pcr0"`
	// IsKMSKeyLocked controls the strictness of the locked KMS key policy:
	//
	//   false (default — absent in yaml gives this) — the policy adds a
	//     RootRecovery statement granting the AWS account root user
	//     kms:PutKeyPolicy, kms:GetKeyPolicy, kms:DescribeKey. Root
	//     explicitly does NOT have kms:Decrypt — recovery means
	//     rewriting the policy to add a new PCR0 condition (and the
	//     freshly-deployed enclave then decrypts). The framework's
	//     "plaintext only inside an attested enclave" invariant holds
	//     even during recovery.
	//
	//   true — strict mode: the locked policy is permanently frozen;
	//     even root cannot rewrite it. Only the attested PCR0 enclave
	//     can decrypt. Permanent at first lock.
	IsKMSKeyLocked bool      `yaml:"is_kms_key_locked"`
	TLS            TLSConfig `yaml:"tls"`
	Nix            NixConfig `yaml:"nix"`
}

// NixConfig configures Nix binary caching and reproducibility for EIF builds.
// Only Cachix is supported as a substituter backend — config-load rejects
// any other URL. NixpkgsRev pins the flake's nixpkgs input to a specific
// commit so the derivation graph is stable across builds.
type NixConfig struct {
	Substituters      []string `yaml:"substituters"`
	TrustedPublicKeys []string `yaml:"trusted_public_keys"`
	NixpkgsRev        string   `yaml:"nixpkgs_rev"`
	NixpkgsHash       string   `yaml:"nixpkgs_hash"`
}

type AppConfig struct {
	Language             string            `yaml:"language"`
	Source               string            `yaml:"source"`
	NixOwner             string            `yaml:"nix_owner"`
	NixRepo              string            `yaml:"nix_repo"`
	NixRev               string            `yaml:"nix_rev"`
	NixHash              string            `yaml:"nix_hash"`
	NixVendorHash        string            `yaml:"nix_vendor_hash"`
	NixSubPackages       []string          `yaml:"nix_sub_packages"`
	NixProjectFile       string            `yaml:"nix_project_file"`
	NixSubdir            string            `yaml:"nix_subdir"`
	NixBuildInputs       []string          `yaml:"nix_build_inputs"`
	NixNativeBuildInputs []string          `yaml:"nix_native_build_inputs"`
	BinaryName           string            `yaml:"binary_name"`
	Env                  map[string]string `yaml:"env"`
	// ReleaseTag identifies the GitHub Release of nix_owner/nix_repo from
	// which `enclave tofu init --remote` downloads image.eif and supervisor.
	// Defaults to "eif-latest" when unset.
	ReleaseTag string `yaml:"release_tag"`
	// Vendor switches the flake into vendor mode — Nix uses a committed
	// vendor/ directory in the source tree instead of fetching deps via
	// cargoHash/vendorHash. Survives upstream dep disappearance regardless
	// of cache state. Only supported for language=go|rust.
	Vendor bool `yaml:"vendor"`
}

// SecretConfig defines a secret managed by KMS inside the enclave.
// Each secret is stored as an encrypted ciphertext in SSM and decrypted
// at boot via KMS attestation. The decrypted value is passed to the
// upstream app as the specified environment variable.
type SecretConfig struct {
	Name   string `yaml:"name" json:"name"`       // SSM parameter name component
	EnvVar string `yaml:"env_var" json:"env_var"` // Env var passed to upstream app
}

// RuntimeConfig defines the SDK coordinates for the enclave supervisor binary.
// These are used by Nix to fetch and build the runtime from source.
type RuntimeConfig struct {
	Rev        string `yaml:"rev"`         // SDK git commit SHA
	Hash       string `yaml:"hash"`        // Nix source hash (SRI format)
	VendorHash string `yaml:"vendor_hash"` // Go vendor hash (SRI format)
}

// TLSConfig selects the cert the enclave serves on its public HTTPS listener.
// It is applied at deploy time (CLI -> tofu -> SSM -> runtime), so changing
// the domain is a redeploy, not an EIF rebuild.
//
//	provider self-signed (default) — the enclave generates a self-signed cert.
//	  Clients trust the connection via the attestation document, which binds
//	  the cert hash into UserData; no CA is involved.
//
//	provider letsencrypt / letsencrypt-staging — the enclave obtains a
//	  CA-issued cert via ACME (TLS-ALPN-01) for FQDN. 'letsencrypt-staging'
//	  uses the Let's Encrypt staging environment (untrusted root, high rate
//	  limits) for testing. FQDN is required for both.
type TLSConfig struct {
	FQDN          string `yaml:"fqdn"`            // domain the cert is issued for
	Provider      string `yaml:"provider"`        // self-signed | letsencrypt | letsencrypt-staging
	Email         string `yaml:"email"`           // optional ACME contact for expiry notices
	Route53ZoneID string `yaml:"route53_zone_id"` // optional; when set, tofu creates an A record for fqdn in this zone
}

func loadConfig() (*Config, error) {
	return loadConfigAt("")
}

// loadConfigAt loads enclave.yaml from an explicit path, or "" to use
// the default resolution (ENCLAVE_CONFIG env override → findRepoRoot).
func loadConfigAt(configPath string) (*Config, error) {
	if configPath == "" {
		configPath = os.Getenv("ENCLAVE_CONFIG")
	}
	if configPath == "" {
		root, err := findRepoRoot()
		if err != nil {
			return nil, err
		}
		configPath = resolveConfigPath(root)
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
	if cfg.Deployment == "" {
		cfg.Deployment = "dev"
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
	if cfg.App.ReleaseTag == "" {
		cfg.App.ReleaseTag = "eif-latest"
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
	if cfg.MigrationIntentRetention == "" {
		cfg.MigrationIntentRetention = "87600h"
	}
	retention, err := time.ParseDuration(cfg.MigrationIntentRetention)
	if err != nil || retention <= 0 {
		return nil, fmt.Errorf("%s: invalid migration_intent_retention %q", configFile, cfg.MigrationIntentRetention)
	}
	if cfg.PreviousPCR0 == "" {
		cfg.PreviousPCR0 = "genesis"
	}
	if cfg.TLS.Provider == "" {
		cfg.TLS.Provider = "self-signed"
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

	// Validate TLS config.
	switch cfg.TLS.Provider {
	case "self-signed", "letsencrypt", "letsencrypt-staging":
	default:
		return nil, fmt.Errorf("%s: tls.provider %q must be one of self-signed, letsencrypt, letsencrypt-staging", configFile, cfg.TLS.Provider)
	}
	if cfg.TLS.Provider != "self-signed" && cfg.TLS.FQDN == "" {
		return nil, fmt.Errorf("%s: tls.fqdn is required when tls.provider is %q", configFile, cfg.TLS.Provider)
	}
	if cfg.TLS.FQDN != "" && !fqdnRegex.MatchString(cfg.TLS.FQDN) {
		return nil, fmt.Errorf("%s: tls.fqdn %q is not a valid domain name", configFile, cfg.TLS.FQDN)
	}
	if cfg.TLS.Route53ZoneID != "" && cfg.TLS.FQDN == "" {
		return nil, fmt.Errorf("%s: tls.route53_zone_id requires tls.fqdn to be set", configFile)
	}

	if cfg.App.Vendor {
		switch cfg.App.Language {
		case "go", "rust":
		default:
			return nil, fmt.Errorf("%s: app.vendor=true is only supported for language go|rust (got %q) — Node uses npmDepsHash and .NET uses nugetDeps, both already manifest-pinned", configFile, cfg.App.Language)
		}
		if cfg.App.NixVendorHash != "" {
			return nil, fmt.Errorf("%s: app.vendor=true is mutually exclusive with app.nix_vendor_hash — clear nix_vendor_hash to switch to vendor mode (vendor mode uses the committed vendor/ directory; no hash needed)", configFile)
		}
	}

	if err := validateNixConfig(&cfg.Nix, configPath); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateNixConfig enforces the Cachix-only substituter rule and the
// well-formed-pin invariant. Substituters must be https://<name>.cachix.org;
// any other URL is rejected. NixpkgsRev/Hash must both be set together.
func validateNixConfig(n *NixConfig, configPath string) error {
	if len(n.Substituters) > 0 && len(n.TrustedPublicKeys) == 0 {
		return fmt.Errorf("%s: nix.substituters set but nix.trusted_public_keys empty (Cachix shows the public key on the cache settings page)", configPath)
	}
	for i, s := range n.Substituters {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || !cachixHostRegex.MatchString(u.Host) {
			return fmt.Errorf("%s: nix.substituters[%d] %q is not a Cachix URL — only https://<name>.cachix.org is supported", configPath, i, s)
		}
		if u.Path != "" && u.Path != "/" {
			return fmt.Errorf("%s: nix.substituters[%d] %q must not include a path", configPath, i, s)
		}
	}
	for i, k := range n.TrustedPublicKeys {
		if !publicKeyRegex.MatchString(k) {
			return fmt.Errorf("%s: nix.trusted_public_keys[%d] %q must be in <name>:<base64> format", configPath, i, k)
		}
	}
	if n.NixpkgsRev != "" || n.NixpkgsHash != "" {
		if n.NixpkgsRev == "" || n.NixpkgsHash == "" {
			return fmt.Errorf("%s: nix.nixpkgs_rev and nix.nixpkgs_hash must both be set (use `enclave nixpkgs pin`)", configPath)
		}
		if !commitSHARegex.MatchString(n.NixpkgsRev) {
			return fmt.Errorf("%s: nix.nixpkgs_rev %q must be a 40-char hex commit SHA", configPath, n.NixpkgsRev)
		}
		if !sriSha256Regex.MatchString(n.NixpkgsHash) {
			return fmt.Errorf("%s: nix.nixpkgs_hash %q must be SRI-formatted sha256 ('sha256-' + 43 base64 chars + '=')", configPath, n.NixpkgsHash)
		}
	}
	return nil
}

// CachixCacheName extracts the cache name from a Cachix substituter URL.
// Returns "" if the URL is not a well-formed Cachix URL (wrong scheme, host,
// or includes any path/query/fragment).
func CachixCacheName(substituter string) string {
	u, err := url.Parse(substituter)
	if err != nil || u.Scheme != "https" || !cachixHostRegex.MatchString(u.Host) {
		return ""
	}
	if u.Path != "" && u.Path != "/" {
		return ""
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return strings.TrimSuffix(u.Host, ".cachix.org")
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

// validateRuntime checks that runtime coordinates are present. Only needed for commands
// that build the EIF (build, deploy), not for status/verify/destroy/lock.
func (c *Config) validateRuntime() error {
	if c.Runtime.Rev == "" {
		return fmt.Errorf("%s: 'runtime.rev' is required (runtime commit SHA)", configFile)
	}
	if c.Runtime.Hash == "" {
		return fmt.Errorf("%s: 'runtime.hash' is required (Nix source hash)", configFile)
	}
	if c.Runtime.VendorHash == "" {
		return fmt.Errorf("%s: 'runtime.vendor_hash' is required (Go vendor hash)", configFile)
	}
	return nil
}

// resolveConfigPath returns the path to enclave.yaml under root, accepting
// either the canonical enclave/enclave.yaml or a bare enclave.yaml at the
// project root. Falls back to the canonical path when neither exists, so
// downstream errors point at the conventional location.
func resolveConfigPath(root string) string {
	canonical := filepath.Join(root, configFile)
	if _, err := os.Stat(canonical); err == nil {
		return canonical
	}
	bare := filepath.Join(root, configFileBare)
	if _, err := os.Stat(bare); err == nil {
		return bare
	}
	return canonical
}

// findRepoRoot walks up from cwd looking for an enclave.yaml (in either layout)
// or a .git boundary.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, configFile)); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, configFileBare)); err == nil {
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
