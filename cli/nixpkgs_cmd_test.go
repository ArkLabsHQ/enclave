package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testRev  = "0d843eedba88d22a7eaa2a7e54a2c1d8c0c0d4f8"
	// SRI sha256 of the empty string (43 base64 chars + "=") — real, valid.
	testHash = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
)

func TestUpdateNixpkgsInYaml_AppendsBlockWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enclave.yaml")
	original := "name: myapp\nregion: us-east-1\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := updateNixpkgsInYaml(path, testRev, testHash); err != nil {
		t.Fatalf("updateNixpkgsInYaml: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(got)
	if !strings.Contains(out, "nix:") {
		t.Errorf("expected nix: block to be appended, got:\n%s", out)
	}
	if !strings.Contains(out, testRev) {
		t.Errorf("expected rev in output, got:\n%s", out)
	}
	if !strings.Contains(out, testHash) {
		t.Errorf("expected hash in output, got:\n%s", out)
	}
	if !strings.Contains(out, "name: myapp") {
		t.Errorf("original content lost, got:\n%s", out)
	}
}

func TestUpdateNixpkgsInYaml_UpdatesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enclave.yaml")
	original := `name: myapp
region: us-east-1

# Important comment above nix block
nix:
  substituters:
    - "https://merlin.cachix.org"
  trusted_public_keys:
    - "merlin.cachix.org-1:abc="
  nixpkgs_rev:  "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
  nixpkgs_hash: "sha256-OLDHASH=="
`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := updateNixpkgsInYaml(path, testRev, testHash); err != nil {
		t.Fatalf("updateNixpkgsInYaml: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(got)
	if strings.Contains(out, "deadbeef") {
		t.Errorf("old rev should have been replaced, got:\n%s", out)
	}
	if strings.Contains(out, "OLDHASH") {
		t.Errorf("old hash should have been replaced, got:\n%s", out)
	}
	if !strings.Contains(out, testRev) || !strings.Contains(out, testHash) {
		t.Errorf("new pin values missing, got:\n%s", out)
	}
	if !strings.Contains(out, "# Important comment above nix block") {
		t.Errorf("comments must be preserved, got:\n%s", out)
	}
	if !strings.Contains(out, `- "https://merlin.cachix.org"`) {
		t.Errorf("substituters list must be preserved, got:\n%s", out)
	}
}

func TestUpdateNixpkgsInYaml_InsertsUnderExistingNixBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enclave.yaml")
	// nix block exists but lacks the pin fields.
	original := `name: myapp
region: us-east-1
nix:
  substituters:
    - "https://merlin.cachix.org"
  trusted_public_keys:
    - "merlin.cachix.org-1:abc="
`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	if err := updateNixpkgsInYaml(path, testRev, testHash); err != nil {
		t.Fatalf("updateNixpkgsInYaml: %v", err)
	}

	got, _ := os.ReadFile(path)
	out := string(got)
	if !strings.Contains(out, testRev) || !strings.Contains(out, testHash) {
		t.Errorf("missing pin values, got:\n%s", out)
	}
	if !strings.Contains(out, `- "https://merlin.cachix.org"`) {
		t.Errorf("existing substituters dropped, got:\n%s", out)
	}
}

func TestUpdateNixpkgsInFlake_RewritesURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flake.nix")
	original := `{
  description = "test";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };
}
`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	if err := updateNixpkgsInFlake(path, testRev); err != nil {
		t.Fatalf("updateNixpkgsInFlake: %v", err)
	}
	got, _ := os.ReadFile(path)
	out := string(got)
	want := `nixpkgs.url = "github:NixOS/nixpkgs/` + testRev + `"`
	if !strings.Contains(out, want) {
		t.Errorf("expected URL rewritten, got:\n%s", out)
	}
	if strings.Contains(out, "nixos-25.11") {
		t.Errorf("old branch ref should be gone, got:\n%s", out)
	}
	if !strings.Contains(out, "flake-utils") {
		t.Errorf("other inputs must be preserved, got:\n%s", out)
	}
}

func TestUpdateNixpkgsInFlake_NoOpIfNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flake.nix")
	original := `{ description = "no nixpkgs here"; }
`
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	if err := updateNixpkgsInFlake(path, testRev); err != nil {
		t.Fatalf("updateNixpkgsInFlake: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != original {
		t.Errorf("expected file unchanged, got:\n%s", string(got))
	}
}

func TestApplyNixpkgsRef_UsesDefaultWhenEmpty(t *testing.T) {
	template := `nixpkgs.url = "github:NixOS/nixpkgs/{{NixpkgsRef}}";`
	out := applyNixpkgsRef(template, "")
	if !strings.Contains(out, DefaultNixpkgsRef) {
		t.Errorf("expected default ref to be used, got: %s", out)
	}
}

func TestApplyNixpkgsRef_SubstitutesProvidedRef(t *testing.T) {
	template := `nixpkgs.url = "github:NixOS/nixpkgs/{{NixpkgsRef}}";`
	out := applyNixpkgsRef(template, testRev)
	if !strings.Contains(out, testRev) {
		t.Errorf("expected provided ref, got: %s", out)
	}
	if strings.Contains(out, "{{NixpkgsRef}}") {
		t.Errorf("placeholder should be gone, got: %s", out)
	}
}

func TestGetInitFilesWithNixpkgs_PreservesOperatorPin(t *testing.T) {
	pinSHA := "0d843eedba88d22a7eaa2a7e54a2c1d8c0c0d4f8"
	for _, lang := range []string{"go", "nodejs", "dotnet", "rust"} {
		t.Run(lang, func(t *testing.T) {
			files := getInitFilesWithNixpkgs(lang, pinSHA)
			var flake string
			for _, f := range files {
				if f.RelPath == "enclave/flake.nix" {
					flake = f.Content
				}
			}
			if flake == "" {
				t.Fatal("no flake.nix in init files")
			}
			if !strings.Contains(flake, pinSHA) {
				t.Errorf("operator's pin %q missing from scaffolded flake.nix — setup --force-flake regression risk", pinSHA)
			}
			if strings.Contains(flake, DefaultNixpkgsRef) {
				t.Errorf("default ref %q leaked into scaffolded flake when operator pin was provided", DefaultNixpkgsRef)
			}
		})
	}
}

func TestGetInitFiles_FlakeHasResolvedRefs(t *testing.T) {
	placeholders := []string{
		"{{NixpkgsRef}}",
		"{{FlakeUtilsRef}}",
		"{{AwsNitroUtilRef}}",
	}
	followsDecls := []string{
		`aws-nitro-util.inputs.nixpkgs.follows = "nixpkgs"`,
		`aws-nitro-util.inputs.flake-utils.follows = "flake-utils"`,
		`flake-utils.inputs.systems.follows = ""`,
	}
	for _, lang := range []string{"go", "nodejs", "dotnet", "rust"} {
		t.Run(lang, func(t *testing.T) {
			files := getInitFiles(lang)
			var flake string
			for _, f := range files {
				if f.RelPath == "enclave/flake.nix" {
					flake = f.Content
				}
			}
			if flake == "" {
				t.Fatal("no flake.nix in init files")
			}
			for _, p := range placeholders {
				if strings.Contains(flake, p) {
					t.Errorf("placeholder %s leaked into scaffolded flake.nix", p)
				}
			}
			if !strings.Contains(flake, DefaultNixpkgsRef) {
				t.Errorf("expected DefaultNixpkgsRef in scaffolded flake.nix")
			}
			if !strings.Contains(flake, FlakeUtilsRef) {
				t.Errorf("expected FlakeUtilsRef in scaffolded flake.nix")
			}
			if !strings.Contains(flake, AwsNitroUtilRef) {
				t.Errorf("expected AwsNitroUtilRef in scaffolded flake.nix")
			}
			for _, decl := range followsDecls {
				if !strings.Contains(flake, decl) {
					t.Errorf("expected follows declaration %q in scaffolded flake.nix", decl)
				}
			}
		})
	}
}

func TestApplyNixpkgsRef_SubstitutesFrameworkPins(t *testing.T) {
	template := `inputs = {
  nixpkgs.url = "github:NixOS/nixpkgs/{{NixpkgsRef}}";
  flake-utils.url = "github:numtide/flake-utils/{{FlakeUtilsRef}}";
  aws-nitro-util.url = "github:monzo/aws-nitro-util/{{AwsNitroUtilRef}}";
};`
	out := applyNixpkgsRef(template, "custom-pin")
	if !strings.Contains(out, "custom-pin") {
		t.Errorf("nixpkgs override not applied, got: %s", out)
	}
	if !strings.Contains(out, FlakeUtilsRef) {
		t.Errorf("FlakeUtilsRef not substituted, got: %s", out)
	}
	if !strings.Contains(out, AwsNitroUtilRef) {
		t.Errorf("AwsNitroUtilRef not substituted, got: %s", out)
	}
	for _, p := range []string{"{{NixpkgsRef}}", "{{FlakeUtilsRef}}", "{{AwsNitroUtilRef}}"} {
		if strings.Contains(out, p) {
			t.Errorf("placeholder %s leaked, got: %s", p, out)
		}
	}
}

func TestRunPinCheck_RejectsInvalidPin(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
	}{
		{"no pin", &Config{}},
		{"short rev", &Config{Nix: NixConfig{NixpkgsRev: "abc", NixpkgsHash: testHash}}},
		{"hash missing prefix", &Config{Nix: NixConfig{NixpkgsRev: testRev, NixpkgsHash: "abc"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := runPinCheck(tt.cfg); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestRunPinCheck_AcceptsValidPin(t *testing.T) {
	cfg := &Config{Nix: NixConfig{NixpkgsRev: testRev, NixpkgsHash: testHash}}
	if err := runPinCheck(cfg); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDecodeNixBase32_AllZeros(t *testing.T) {
	// Index 0 in the Nix base32 alphabet is '0', so a string of 52 zeros
	// decodes to 32 zero bytes.
	out, err := decodeNixBase32(strings.Repeat("0", 52))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(out))
	}
	for i, b := range out {
		if b != 0 {
			t.Errorf("byte %d = %d, want 0", i, b)
		}
	}
}

func TestDecodeNixBase32_RejectsWrongLength(t *testing.T) {
	if _, err := decodeNixBase32("abc"); err == nil {
		t.Error("expected error for short input")
	}
}

func TestDecodeNixBase32_RejectsInvalidChar(t *testing.T) {
	// 'e', 'o', 't', 'u' are NOT in the Nix base32 alphabet.
	in := strings.Repeat("0", 51) + "e"
	if _, err := decodeNixBase32(in); err == nil {
		t.Error("expected error for invalid char")
	}
}

func TestNixHashToSRI_PassThroughSRI(t *testing.T) {
	out, err := nixHashToSRI(testHash)
	if err != nil {
		t.Fatalf("nixHashToSRI: %v", err)
	}
	if out != testHash {
		t.Errorf("expected pass-through, got %q", out)
	}
}
