package introspector_enclave

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGenerateBuildConfig(t *testing.T) {
	root := t.TempDir()
	// Create enclave/ directory (generateBuildConfig writes to enclave/build-config.json).
	if err := os.MkdirAll(filepath.Join(root, "enclave"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Name:    "testapp",
		Version: "1.2.3",
		Region:  "us-west-2",
		Prefix:  "staging",
		App: AppConfig{
			Language:       "go",
			NixOwner:       "myorg",
			NixRepo:        "myrepo",
			NixRev:         "abc123",
			NixHash:        "sha256-src",
			NixVendorHash:  "sha256-vendor",
			NixSubPackages: []string{"cmd/server"},
			NixSubdir:      "backend",
			BinaryName:     "myserver",
			Env: map[string]string{
				"CUSTOM_VAR": "hello",
			},
		},
		Secrets: []SecretConfig{
			{Name: "db_key", EnvVar: "DB_KEY"},
		},
		SDK: SDKConfig{
			Rev: "sdkrev", Hash: "sha256-sdk", VendorHash: "sha256-sdkv",
		},
		MigrationCooldown: "5m",
		PreviousPCR0:      "genesis",
	}

	if err := generateBuildConfig(cfg, root); err != nil {
		t.Fatalf("generateBuildConfig: %v", err)
	}

	// Read and parse the generated JSON.
	data, err := os.ReadFile(filepath.Join(root, "enclave", "build-config.json"))
	if err != nil {
		t.Fatalf("read build-config.json: %v", err)
	}

	var bc buildConfigJSON
	if err := json.Unmarshal(data, &bc); err != nil {
		t.Fatalf("parse build-config.json: %v", err)
	}

	if bc.Name != "testapp" {
		t.Errorf("Name = %q, want %q", bc.Name, "testapp")
	}
	if bc.Region != "us-west-2" {
		t.Errorf("Region = %q, want %q", bc.Region, "us-west-2")
	}
	if bc.App.NixSubdir != "backend" {
		t.Errorf("App.NixSubdir = %q, want %q", bc.App.NixSubdir, "backend")
	}
	if bc.App.BinaryName != "myserver" {
		t.Errorf("App.BinaryName = %q, want %q", bc.App.BinaryName, "myserver")
	}
	// APP_BINARY_NAME should be injected.
	if bc.App.Env["APP_BINARY_NAME"] != "myserver" {
		t.Errorf("Env[APP_BINARY_NAME] = %q, want %q", bc.App.Env["APP_BINARY_NAME"], "myserver")
	}
	if bc.App.Env["CUSTOM_VAR"] != "hello" {
		t.Errorf("Env[CUSTOM_VAR] = %q, want %q", bc.App.Env["CUSTOM_VAR"], "hello")
	}
	if len(bc.Secrets) != 1 || bc.Secrets[0].Name != "db_key" {
		t.Errorf("Secrets = %v, want [{db_key DB_KEY}]", bc.Secrets)
	}
	if bc.SDK.Rev != "sdkrev" {
		t.Errorf("SDK.Rev = %q, want %q", bc.SDK.Rev, "sdkrev")
	}
}

func TestGenerateBuildConfig_EnvTemplateSubstitution(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "enclave"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Name:    "app",
		Version: "2.0.0",
		Region:  "eu-west-1",
		Prefix:  "prod",
		App: AppConfig{
			BinaryName: "app",
			Env: map[string]string{
				"DEPLOY_REGION":  "{{region}}",
				"DEPLOY_PREFIX":  "{{prefix}}",
				"DEPLOY_VERSION": "{{version}}",
			},
		},
		MigrationCooldown: "0s",
		PreviousPCR0:      "genesis",
	}

	if err := generateBuildConfig(cfg, root); err != nil {
		t.Fatalf("generateBuildConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "enclave", "build-config.json"))
	if err != nil {
		t.Fatal(err)
	}

	var bc buildConfigJSON
	if err := json.Unmarshal(data, &bc); err != nil {
		t.Fatal(err)
	}

	if bc.App.Env["DEPLOY_REGION"] != "eu-west-1" {
		t.Errorf("{{region}} not resolved: got %q", bc.App.Env["DEPLOY_REGION"])
	}
	if bc.App.Env["DEPLOY_PREFIX"] != "prod" {
		t.Errorf("{{prefix}} not resolved: got %q", bc.App.Env["DEPLOY_PREFIX"])
	}
	if bc.App.Env["DEPLOY_VERSION"] != "2.0.0" {
		t.Errorf("{{version}} not resolved: got %q", bc.App.Env["DEPLOY_VERSION"])
	}
}

func TestNonNilStrings(t *testing.T) {
	if got := nonNilStrings(nil); !reflect.DeepEqual(got, []string{}) {
		t.Errorf("nonNilStrings(nil) = %v, want []", got)
	}
	in := []string{"openssl", "protobuf"}
	if got := nonNilStrings(in); !reflect.DeepEqual(got, in) {
		t.Errorf("nonNilStrings(%v) = %v, want %v", in, got, in)
	}
	if got := nonNilStrings([]string{}); !reflect.DeepEqual(got, []string{}) {
		t.Errorf("nonNilStrings([]) = %v, want []", got)
	}
}

// TestGenerateBuildConfig_BuildInputs verifies that user-supplied
// nix_build_inputs / nix_native_build_inputs flow through into the
// generated build-config.json.
func TestGenerateBuildConfig_BuildInputs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "enclave"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Name:    "app",
		Version: "1.0.0",
		Region:  "us-east-1",
		App: AppConfig{
			BinaryName:           "app",
			NixBuildInputs:       []string{"openssl", "zlib"},
			NixNativeBuildInputs: []string{"pkg-config", "protobuf"},
		},
		MigrationCooldown: "0s",
		PreviousPCR0:      "genesis",
	}

	if err := generateBuildConfig(cfg, root); err != nil {
		t.Fatalf("generateBuildConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "enclave", "build-config.json"))
	if err != nil {
		t.Fatal(err)
	}

	var bc buildConfigJSON
	if err := json.Unmarshal(data, &bc); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(bc.App.NixBuildInputs, []string{"openssl", "zlib"}) {
		t.Errorf("NixBuildInputs = %v, want [openssl zlib]", bc.App.NixBuildInputs)
	}
	if !reflect.DeepEqual(bc.App.NixNativeBuildInputs, []string{"pkg-config", "protobuf"}) {
		t.Errorf("NixNativeBuildInputs = %v, want [pkg-config protobuf]", bc.App.NixNativeBuildInputs)
	}
}

// TestGenerateBuildConfig_BuildInputsNeverNull ensures that when the user
// omits the two fields in enclave.yaml (so the slices are nil in Go),
// the generated JSON contains empty arrays rather than null. The flake's
// resolveInputs helper expects a list, not null.
func TestGenerateBuildConfig_BuildInputsNeverNull(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "enclave"), 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Name:              "app",
		Version:           "1.0.0",
		Region:            "us-east-1",
		App:               AppConfig{BinaryName: "app"}, // NixBuildInputs: nil, NixNativeBuildInputs: nil
		MigrationCooldown: "0s",
		PreviousPCR0:      "genesis",
	}

	if err := generateBuildConfig(cfg, root); err != nil {
		t.Fatalf("generateBuildConfig: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, "enclave", "build-config.json"))
	if err != nil {
		t.Fatal(err)
	}

	raw := string(data)
	if !strings.Contains(raw, `"nix_build_inputs": []`) {
		t.Errorf("expected empty array for nix_build_inputs, got JSON:\n%s", raw)
	}
	if !strings.Contains(raw, `"nix_native_build_inputs": []`) {
		t.Errorf("expected empty array for nix_native_build_inputs, got JSON:\n%s", raw)
	}
	if strings.Contains(raw, `"nix_build_inputs": null`) || strings.Contains(raw, `"nix_native_build_inputs": null`) {
		t.Errorf("JSON must not emit null for build-input lists, got:\n%s", raw)
	}
}
