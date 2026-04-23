package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig creates a temporary enclave.yaml and sets ENCLAVE_CONFIG.
// Returns a cleanup function to restore the env.
func writeConfig(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "enclave.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCLAVE_CONFIG", path)
}

func TestLoadConfig_ValidComplete(t *testing.T) {
	writeConfig(t, `
name: myapp
version: "1.0.0"
region: us-east-1
account: "123456789012"
prefix: prod
instance_type: c6i.xlarge
migration_cooldown: "5m"
previous_pcr0: abc123
app:
  language: rust
  nix_owner: myorg
  nix_repo: myrepo
  nix_rev: deadbeef
  nix_hash: "sha256-abc"
  nix_vendor_hash: "sha256-def"
  binary_name: mybin
secrets:
  - name: db_key
    env_var: DB_KEY
sdk:
  rev: abc123
  hash: "sha256-sdk"
  vendor_hash: "sha256-sdkv"
`)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.Name != "myapp" {
		t.Errorf("Name = %q, want %q", cfg.Name, "myapp")
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", cfg.Version, "1.0.0")
	}
	if cfg.Prefix != "prod" {
		t.Errorf("Prefix = %q, want %q", cfg.Prefix, "prod")
	}
	if cfg.InstanceType != "c6i.xlarge" {
		t.Errorf("InstanceType = %q, want %q", cfg.InstanceType, "c6i.xlarge")
	}
	if cfg.App.Language != "rust" {
		t.Errorf("App.Language = %q, want %q", cfg.App.Language, "rust")
	}
	if cfg.App.BinaryName != "mybin" {
		t.Errorf("App.BinaryName = %q, want %q", cfg.App.BinaryName, "mybin")
	}
	if cfg.MigrationCooldown != "5m" {
		t.Errorf("MigrationCooldown = %q, want %q", cfg.MigrationCooldown, "5m")
	}
	if cfg.PreviousPCR0 != "abc123" {
		t.Errorf("PreviousPCR0 = %q, want %q", cfg.PreviousPCR0, "abc123")
	}
	if len(cfg.Secrets) != 1 || cfg.Secrets[0].Name != "db_key" {
		t.Errorf("Secrets = %v, want [{db_key DB_KEY}]", cfg.Secrets)
	}
}

func TestLoadConfig_BuildInputs(t *testing.T) {
	writeConfig(t, `
name: myapp
region: us-east-1
app:
  language: rust
  nix_build_inputs:
    - openssl
    - zlib
  nix_native_build_inputs:
    - pkg-config
    - protobuf
`)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got, want := cfg.App.NixBuildInputs, []string{"openssl", "zlib"}; !equalStrings(got, want) {
		t.Errorf("NixBuildInputs = %v, want %v", got, want)
	}
	if got, want := cfg.App.NixNativeBuildInputs, []string{"pkg-config", "protobuf"}; !equalStrings(got, want) {
		t.Errorf("NixNativeBuildInputs = %v, want %v", got, want)
	}
}

func TestLoadConfig_BuildInputsOmitted(t *testing.T) {
	writeConfig(t, `
name: myapp
region: us-east-1
`)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.App.NixBuildInputs != nil {
		t.Errorf("NixBuildInputs = %v, want nil when omitted", cfg.App.NixBuildInputs)
	}
	if cfg.App.NixNativeBuildInputs != nil {
		t.Errorf("NixNativeBuildInputs = %v, want nil when omitted", cfg.App.NixNativeBuildInputs)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLoadConfig_Defaults(t *testing.T) {
	writeConfig(t, `
name: minimal
region: eu-west-1
`)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.Prefix != "dev" {
		t.Errorf("Prefix = %q, want %q", cfg.Prefix, "dev")
	}
	if cfg.Version != "dev" {
		t.Errorf("Version = %q, want %q", cfg.Version, "dev")
	}
	if cfg.InstanceType != "m6i.xlarge" {
		t.Errorf("InstanceType = %q, want %q", cfg.InstanceType, "m6i.xlarge")
	}
	if cfg.App.BinaryName != "minimal" {
		t.Errorf("App.BinaryName = %q, want %q (should default to name)", cfg.App.BinaryName, "minimal")
	}
	if cfg.App.Source != "nix" {
		t.Errorf("App.Source = %q, want %q", cfg.App.Source, "nix")
	}
	if cfg.App.Language != "go" {
		t.Errorf("App.Language = %q, want %q", cfg.App.Language, "go")
	}
	if cfg.MigrationCooldown != "0s" {
		t.Errorf("MigrationCooldown = %q, want %q", cfg.MigrationCooldown, "0s")
	}
	if cfg.PreviousPCR0 != "genesis" {
		t.Errorf("PreviousPCR0 = %q, want %q", cfg.PreviousPCR0, "genesis")
	}
}

func TestLoadConfig_MissingName(t *testing.T) {
	writeConfig(t, `
region: us-east-1
`)
	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestLoadConfig_MissingRegion(t *testing.T) {
	writeConfig(t, `
name: myapp
`)
	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for missing region")
	}
}

func TestLoadConfig_InvalidMigrationCooldown(t *testing.T) {
	writeConfig(t, `
name: myapp
region: us-east-1
migration_cooldown: "not-a-duration"
`)
	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for invalid migration_cooldown")
	}
}

func TestLoadConfig_SecretValidation(t *testing.T) {
	tests := []struct {
		name    string
		secrets string
	}{
		{
			name: "duplicate name",
			secrets: `
secrets:
  - name: key1
    env_var: KEY_ONE
  - name: key1
    env_var: KEY_TWO`,
		},
		{
			name: "duplicate env_var",
			secrets: `
secrets:
  - name: key1
    env_var: MY_KEY
  - name: key2
    env_var: MY_KEY`,
		},
		{
			name: "reserved ENCLAVE_ prefix",
			secrets: `
secrets:
  - name: key1
    env_var: ENCLAVE_SECRET`,
		},
		{
			name: "reserved AWS_ prefix",
			secrets: `
secrets:
  - name: key1
    env_var: AWS_SECRET`,
		},
		{
			name: "invalid secret name format",
			secrets: `
secrets:
  - name: 1invalid
    env_var: MY_KEY`,
		},
		{
			name: "invalid env_var format",
			secrets: `
secrets:
  - name: valid
    env_var: lowercase`,
		},
		{
			name: "missing secret name",
			secrets: `
secrets:
  - name: ""
    env_var: MY_KEY`,
		},
		{
			name: "missing env_var",
			secrets: `
secrets:
  - name: key1
    env_var: ""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeConfig(t, "name: myapp\nregion: us-east-1\n"+tt.secrets)
			_, err := loadConfig()
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestValidateAccount(t *testing.T) {
	tests := []struct {
		account string
		wantErr bool
	}{
		{"123456789012", false},
		{"", true},
		{"12345", true},
		{"abcdefghijkl", true},
		{"1234567890123", true},
	}

	for _, tt := range tests {
		t.Run(tt.account, func(t *testing.T) {
			cfg := &Config{Account: tt.account}
			err := cfg.validateAccount()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAccount(%q) error = %v, wantErr = %v", tt.account, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSDK(t *testing.T) {
	valid := &Config{Runtime: RuntimeConfig{Rev: "abc", Hash: "sha256-x", VendorHash: "sha256-y"}}
	if err := valid.validateRuntime(); err != nil {
		t.Errorf("valid runtime: %v", err)
	}

	for _, field := range []string{"rev", "hash", "vendor_hash"} {
		t.Run("missing_"+field, func(t *testing.T) {
			sdk := RuntimeConfig{Rev: "abc", Hash: "sha256-x", VendorHash: "sha256-y"}
			switch field {
			case "rev":
				sdk.Rev = ""
			case "hash":
				sdk.Hash = ""
			case "vendor_hash":
				sdk.VendorHash = ""
			}
			cfg := &Config{Runtime: sdk}
			if err := cfg.validateRuntime(); err == nil {
				t.Errorf("expected error for missing %s", field)
			}
		})
	}
}
