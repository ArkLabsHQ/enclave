package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testYAML = `name: myapp
region: us-east-1
account: "123456789012"
prefix: dev
runtime:
  rev: x
  hash: sha256-x
  vendor_hash: sha256-y
app:
  language: go
  nix_owner: ArkLabsHQ
  nix_repo: introspector-enclave
  nix_rev: x
  nix_hash: sha256-x
  nix_vendor_hash: sha256-y
  binary_name: myapp
secrets: []
tls:
  provider: letsencrypt
  fqdn: api.example.com
  email: ops@example.com
  route53_zone_id: Z123ABCDEFGHIJ
`

// chdirTemp creates a temp dir, chdirs into it, restores cwd on cleanup, and
// returns the temp dir path.
func chdirTemp(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	return tmp
}

// TestWriteTofuVars_Route53ZoneID verifies that tls.route53_zone_id round-trips
// from the loaded Config into terraform.tfvars.json under the expected key.
func TestWriteTofuVars_Route53ZoneID(t *testing.T) {
	cases := []struct {
		name     string
		zoneID   string
		wantJSON string
	}{
		{name: "empty zone id round-trips as empty", zoneID: "", wantJSON: ""},
		{name: "populated zone id round-trips verbatim", zoneID: "Z123456ABCDEFG", wantJSON: "Z123456ABCDEFG"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "tofu"), 0755); err != nil {
				t.Fatal(err)
			}

			cfg := &Config{
				Name:    "myapp",
				Region:  "us-east-1",
				Account: "123456789012",
				Prefix:  "dev",
				TLS: TLSConfig{
					FQDN:          "api.example.com",
					Provider:      "letsencrypt",
					Email:         "ops@example.com",
					Route53ZoneID: tc.zoneID,
				},
			}

			if err := writeTofuVars(cfg, root, true); err != nil {
				t.Fatalf("writeTofuVars: %v", err)
			}

			data, err := os.ReadFile(filepath.Join(root, "tofu", "terraform.tfvars.json"))
			if err != nil {
				t.Fatalf("read tfvars: %v", err)
			}

			var parsed struct {
				TLS struct {
					Route53ZoneID string `json:"route53_zone_id"`
				} `json:"tls"`
			}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("unmarshal tfvars: %v", err)
			}

			if parsed.TLS.Route53ZoneID != tc.wantJSON {
				t.Errorf("tls.route53_zone_id = %q, want %q", parsed.TLS.Route53ZoneID, tc.wantJSON)
			}
		})
	}
}

// TestTofuUpdate_RefreshesOnlyTfvars confirms that `enclave tofu update`
// regenerates terraform.tfvars.json from enclave.yaml while leaving the
// scaffolded module files (main.tf, modules/enclave/main.tf) untouched.
func TestTofuUpdate_RefreshesOnlyTfvars(t *testing.T) {
	tmp := chdirTemp(t)

	if err := os.WriteFile(filepath.Join(tmp, "enclave.yaml"), []byte(testYAML), 0644); err != nil {
		t.Fatal(err)
	}

	sentinelMain := "# SENTINEL main.tf — must not be overwritten\n"
	sentinelModule := "# SENTINEL modules/enclave/main.tf — must not be overwritten\n"
	if err := os.MkdirAll(filepath.Join(tmp, "tofu", "modules", "enclave"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tofu", "main.tf"), []byte(sentinelMain), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "tofu", "modules", "enclave", "main.tf"), []byte(sentinelModule), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := tofuUpdateCmd()
	cmd.SetArgs([]string{"--remote"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("tofu update: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "tofu", "terraform.tfvars.json"))
	if err != nil {
		t.Fatalf("read tfvars: %v", err)
	}
	var parsed struct {
		TLS struct {
			FQDN          string `json:"fqdn"`
			Route53ZoneID string `json:"route53_zone_id"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal tfvars: %v", err)
	}
	if parsed.TLS.FQDN != "api.example.com" {
		t.Errorf("tls.fqdn = %q, want %q", parsed.TLS.FQDN, "api.example.com")
	}
	if parsed.TLS.Route53ZoneID != "Z123ABCDEFGHIJ" {
		t.Errorf("tls.route53_zone_id = %q, want %q", parsed.TLS.Route53ZoneID, "Z123ABCDEFGHIJ")
	}

	gotMain, _ := os.ReadFile(filepath.Join(tmp, "tofu", "main.tf"))
	if string(gotMain) != sentinelMain {
		t.Errorf("tofu/main.tf was modified; got %q, want %q", gotMain, sentinelMain)
	}
	gotModule, _ := os.ReadFile(filepath.Join(tmp, "tofu", "modules", "enclave", "main.tf"))
	if string(gotModule) != sentinelModule {
		t.Errorf("tofu/modules/enclave/main.tf was modified; got %q, want %q", gotModule, sentinelModule)
	}

	// backend.tf must NOT be written by `enclave tofu update`
	if _, err := os.Stat(filepath.Join(tmp, "tofu", "backend.tf")); !os.IsNotExist(err) {
		t.Errorf("tofu/backend.tf was created by update (or stat failed: %v); should be left alone", err)
	}
}

// TestTofuUpdate_FailsWithoutScaffold confirms `enclave tofu update` refuses
// to run when there's no prior scaffold (tofu/main.tf missing).
func TestTofuUpdate_FailsWithoutScaffold(t *testing.T) {
	tmp := chdirTemp(t)

	if err := os.WriteFile(filepath.Join(tmp, "enclave.yaml"), []byte(testYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := tofuUpdateCmd()
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when tofu/main.tf is missing, got nil")
	}
	if !strings.Contains(err.Error(), "tofu/main.tf not found") {
		t.Errorf("error = %q, want substring 'tofu/main.tf not found'", err.Error())
	}
}
