package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetFrameworkFilesDotnet(t *testing.T) {
	files := getFrameworkFiles("dotnet")

	var foundFlake bool
	for _, f := range files {
		if f.RelPath == "flake.nix" {
			foundFlake = true
			if !strings.Contains(f.Content, "buildDotnetModule") {
				t.Error("dotnet flake.nix should use buildDotnetModule")
			}
			if !strings.Contains(f.Content, "selfContainedBuild") {
				t.Error("dotnet flake.nix should set selfContainedBuild")
			}
			if !strings.Contains(f.Content, "sdk_10_0") {
				t.Error("dotnet flake.nix should use .NET 10 SDK")
			}
		}
	}
	if !foundFlake {
		t.Error("expected flake.nix in framework files")
	}
}

func TestRunGenerateTemplateDotnet(t *testing.T) {
	tmpDir := t.TempDir()

	if err := runGenerateTemplate(tmpDir, "dotnet"); err != nil {
		t.Fatalf("runGenerateTemplate(dotnet): %v", err)
	}

	expectedFiles := []string{
		"flake.nix",
		"enclave/enclave.yaml",
		"enclave/start.sh",
		"Program.cs",
		"MyEnclaveApp.csproj",
		"NuGet.config",
		"README.md",
	}

	for _, name := range expectedFiles {
		path := filepath.Join(tmpDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", name)
		}
	}

	cfgData, err := os.ReadFile(filepath.Join(tmpDir, "enclave", "enclave.yaml"))
	if err != nil {
		t.Fatalf("read enclave.yaml: %v", err)
	}
	cfg := string(cfgData)
	if !strings.Contains(cfg, `language: "dotnet"`) {
		t.Error("enclave.yaml should have language: dotnet")
	}
	if !strings.Contains(cfg, "nix_project_file") {
		t.Error("enclave.yaml should have nix_project_file field")
	}

	csproj, err := os.ReadFile(filepath.Join(tmpDir, "MyEnclaveApp.csproj"))
	if err != nil {
		t.Fatalf("read .csproj: %v", err)
	}
	csprojStr := string(csproj)
	if !strings.Contains(csprojStr, "<Deterministic>true</Deterministic>") {
		t.Error(".csproj should have Deterministic=true")
	}
	if !strings.Contains(csprojStr, "<ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>") {
		t.Error(".csproj should have ContinuousIntegrationBuild=true")
	}
	if !strings.Contains(csprojStr, "PublishAot") {
		t.Error(".csproj should have commented AOT option")
	}

	prog, err := os.ReadFile(filepath.Join(tmpDir, "Program.cs"))
	if err != nil {
		t.Fatalf("read Program.cs: %v", err)
	}
	if !strings.Contains(string(prog), "ENCLAVE_APP_PORT") {
		t.Error("Program.cs should read ENCLAVE_APP_PORT")
	}

	nuget, err := os.ReadFile(filepath.Join(tmpDir, "NuGet.config"))
	if err != nil {
		t.Fatalf("read NuGet.config: %v", err)
	}
	if !strings.Contains(string(nuget), "api.nuget.org") {
		t.Error("NuGet.config should pin to official NuGet feed")
	}
}

func TestGetFrameworkFilesGoUnchanged(t *testing.T) {
	files := getFrameworkFiles("go")
	for _, f := range files {
		if f.RelPath == "flake.nix" {
			if strings.Contains(f.Content, "buildDotnetModule") {
				t.Error("Go flake.nix should NOT contain buildDotnetModule")
			}
			return
		}
	}
	t.Error("expected flake.nix in Go framework files")
}

func TestGetFrameworkFilesNodejsUnchanged(t *testing.T) {
	files := getFrameworkFiles("nodejs")
	for _, f := range files {
		if f.RelPath == "flake.nix" {
			if strings.Contains(f.Content, "buildDotnetModule") {
				t.Error("Node.js flake.nix should NOT contain buildDotnetModule")
			}
			if !strings.Contains(f.Content, "buildNpmPackage") {
				t.Error("Node.js flake.nix should use buildNpmPackage")
			}
			return
		}
	}
	t.Error("expected flake.nix in Node.js framework files")
}

func TestGetFrameworkFilesRust(t *testing.T) {
	files := getFrameworkFiles("rust")
	var foundFlake bool
	for _, f := range files {
		if f.RelPath == "flake.nix" {
			foundFlake = true
			if !strings.Contains(f.Content, "buildRustPackage") {
				t.Error("Rust flake.nix should use buildRustPackage")
			}
			if strings.Contains(f.Content, "buildDotnetModule") {
				t.Error("Rust flake.nix should NOT contain buildDotnetModule")
			}
		}
	}
	if !foundFlake {
		t.Error("expected flake.nix in Rust framework files")
	}
}

func TestRunGenerateTemplateGolang(t *testing.T) {
	tmpDir := t.TempDir()

	if err := runGenerateTemplate(tmpDir, "go"); err != nil {
		t.Fatalf("runGenerateTemplate(go): %v", err)
	}

	expectedFiles := []string{
		"flake.nix",
		"enclave/enclave.yaml",
		"enclave/start.sh",
	}

	for _, name := range expectedFiles {
		path := filepath.Join(tmpDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", name)
		}
	}

	cfgData, err := os.ReadFile(filepath.Join(tmpDir, "enclave", "enclave.yaml"))
	if err != nil {
		t.Fatalf("read enclave.yaml: %v", err)
	}
	if !strings.Contains(string(cfgData), `language: "go"`) {
		t.Error("enclave.yaml should have language: go")
	}
}

// TestFlakeTemplatesHaveBuildInputsPlumbing asserts that every language
// flake template exposes nix_build_inputs / nix_native_build_inputs via
// a resolveInputs helper and wires them into the upstream-app derivation.
// Without this, user-supplied build inputs in enclave.yaml would be
// silently ignored and builds that need native deps (openssl, protoc,
// cairo, ...) would fail.
func TestFlakeTemplatesHaveBuildInputsPlumbing(t *testing.T) {
	for _, lang := range []string{"go", "nodejs", "dotnet", "rust"} {
		t.Run(lang, func(t *testing.T) {
			files := getFrameworkFiles(lang)
			var flake string
			for _, f := range files {
				if f.RelPath == "flake.nix" {
					flake = f.Content
					break
				}
			}
			if flake == "" {
				t.Fatalf("no flake.nix in %s framework files", lang)
			}

			wants := []string{
				"resolveInputs = names:",
				"nativeBuildInputs = resolveInputs (appCfg.nix_native_build_inputs or [])",
				"buildInputs = resolveInputs (appCfg.nix_build_inputs or [])",
			}
			for _, w := range wants {
				if !strings.Contains(flake, w) {
					t.Errorf("%s flake.nix missing: %q", lang, w)
				}
			}
		})
	}
}

// TestEnclaveYamlTemplatesDocumentBuildInputs asserts that every scaffolded
// enclave.yaml exposes the two new fields with a default of [] so users
// discover them without having to read the docs.
func TestEnclaveYamlTemplatesDocumentBuildInputs(t *testing.T) {
	for _, lang := range []string{"go", "nodejs", "dotnet", "rust"} {
		t.Run(lang, func(t *testing.T) {
			tmp := t.TempDir()
			if err := runGenerateTemplate(tmp, lang); err != nil {
				t.Fatalf("runGenerateTemplate(%s): %v", lang, err)
			}
			data, err := os.ReadFile(filepath.Join(tmp, "enclave", "enclave.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			yaml := string(data)
			if !strings.Contains(yaml, "nix_build_inputs: []") {
				t.Errorf("%s enclave.yaml missing nix_build_inputs: []", lang)
			}
			if !strings.Contains(yaml, "nix_native_build_inputs: []") {
				t.Errorf("%s enclave.yaml missing nix_native_build_inputs: []", lang)
			}
		})
	}
}
