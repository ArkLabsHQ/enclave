package introspector_enclave

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
