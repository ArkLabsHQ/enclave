package introspector_enclave

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func generateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate project scaffolding",
	}
	cmd.AddCommand(generateTemplateCmd())
	return cmd
}

func generateTemplateCmd() *cobra.Command {
	var golang, nodejs, dotnet bool

	cmd := &cobra.Command{
		Use:   "template [output-dir]",
		Short: "Generate a complete enclave app template",
		Long: `Generates a ready-to-use project template for building enclave apps.

The output directory will contain framework files, an example app,
enclave.yaml configuration, and GitHub Actions workflows.

Push the result to GitHub and mark it as a template repository
(Settings > General > Template repository).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var language string
			switch {
			case golang:
				language = "go"
			case nodejs:
				language = "nodejs"
			case dotnet:
				language = "dotnet"
			default:
				return fmt.Errorf("specify a language: --golang, --nodejs, or --dotnet")
			}

			outDir := "."
			if len(args) > 0 {
				outDir = args[0]
			}
			return runGenerateTemplate(outDir, language)
		},
	}

	cmd.Flags().BoolVar(&golang, "golang", false, "Generate a Go app template")
	cmd.Flags().BoolVar(&nodejs, "nodejs", false, "Generate a Node.js app template")
	cmd.Flags().BoolVar(&dotnet, "dotnet", false, "Generate a .NET app template")
	return cmd
}

func runGenerateTemplate(outDir, language string) error {
	// Create output directory if needed.
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Write framework files (flake.nix, enclave/, .github/workflows/).
	for _, f := range getFrameworkFiles(language) {
		destPath := filepath.Join(outDir, f.RelPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", f.RelPath, err)
		}
		if err := os.WriteFile(destPath, []byte(f.Content), f.Mode); err != nil {
			return fmt.Errorf("write %s: %w", f.RelPath, err)
		}
		fmt.Printf("  %s\n", f.RelPath)
	}

	// Select language-specific config template and app files.
	var cfgTemplate string
	var appFiles []struct {
		relPath string
		content string
		mode    os.FileMode
	}

	switch language {
	case "nodejs":
		cfgTemplate = nodejsConfigTemplate
		appFiles = []struct {
			relPath string
			content string
			mode    os.FileMode
		}{
			{"index.js", nodejsIndexJs, 0644},
			{"package.json", nodejsPackageJson, 0644},
			{"package-lock.json", nodejsPackageLockJson, 0644},
			{"README.md", templateReadmeNodejs, 0644},
		}
	case "dotnet":
		cfgTemplate = dotnetConfigTemplate
		appFiles = []struct {
			relPath string
			content string
			mode    os.FileMode
		}{
			{"Program.cs", dotnetProgramCs, 0644},
			{"MyEnclaveApp.csproj", dotnetCsproj, 0644},
			{"NuGet.config", dotnetNugetConfig, 0644},
			{"README.md", templateReadmeDotnet, 0644},
		}
	default: // "go"
		cfgTemplate = golangConfigTemplate
		appFiles = []struct {
			relPath string
			content string
			mode    os.FileMode
		}{
			{"cmd/main.go", golangMainGo, 0644},
			{"go.mod", golangGoMod, 0644},
			{"README.md", templateReadmeGolang, 0644},
		}
	}

	// Write enclave.yaml with SDK hashes substituted.
	cfg := cfgTemplate
	if sdkRev != "" {
		cfg = strings.Replace(cfg,
			`  rev: ""                        # SDK git commit SHA (required)`,
			fmt.Sprintf(`  rev: "%s"`, sdkRev), 1)
		cfg = strings.Replace(cfg,
			`  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)`,
			fmt.Sprintf(`  hash: "%s"`, sdkHash), 1)
		cfg = strings.Replace(cfg,
			`  vendor_hash: ""                # Go vendor hash (required)`,
			fmt.Sprintf(`  vendor_hash: "%s"`, sdkVendorHash), 1)
	}
	cfgPath := filepath.Join(outDir, "enclave", "enclave.yaml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		return fmt.Errorf("create enclave/ directory: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		return fmt.Errorf("write enclave/enclave.yaml: %w", err)
	}
	fmt.Println("  enclave/enclave.yaml")

	// Write language-specific app files.
	for _, f := range appFiles {
		destPath := filepath.Join(outDir, f.relPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", f.relPath, err)
		}
		if err := os.WriteFile(destPath, []byte(f.content), f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.relPath, err)
		}
		fmt.Printf("  %s\n", f.relPath)
	}

	fmt.Println()
	fmt.Println("Template generated. Next steps:")
	fmt.Println("  1. Edit enclave/enclave.yaml (set account, name, secrets)")
	fmt.Println("  2. Push to GitHub and mark as a template repository")
	fmt.Println("     (Settings > General > Template repository)")
	return nil
}

// --- Go template constants ---

const golangConfigTemplate = `# Enclave configuration
# Edit this file then run: enclave init

name: my-app                     # App name (used in stack name, EIF name)
version: dev                     # Build version (baked into binary via ldflags)
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
nix_image: nixos/nix:2.24.9      # Docker image for reproducible builds

# SDK coordinates for the enclave supervisor binary.
# The supervisor handles attestation, secrets, PCR extension, and signing
# middleware automatically. Your app is a plain HTTP server with zero SDK imports.
sdk:
  rev: ""                        # SDK git commit SHA (required)
  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)
  vendor_hash: ""                # Go vendor hash (required)

app:
  language: "go"                 # App language: go, nodejs, dotnet
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave.
  # Your app is a normal Go HTTP server that listens on ENCLAVE_APP_PORT (default 7074).
  # Secrets are passed as environment variables. No SDK imports needed.
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_vendor_hash: ""            # Go vendor hash (required)
  nix_sub_packages:              # Go sub-packages to build
    - "cmd"
  binary_name: ""                # Output binary name (defaults to 'name')

  # Environment variables baked into the EIF.
  # Template vars: {{region}}, {{prefix}}, {{version}}
  env:
    # MY_APP_DATA_DIR: /app/data
    # MY_APP_REGION: "{{region}}"

# Secrets managed by KMS inside the enclave.
# Each secret is generated as 32 random bytes, encrypted with KMS,
# stored in SSM, and decrypted at boot via attestation.
# The decrypted value (hex-encoded) is set as the specified env var.
secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
  # - name: api_token
  #   env_var: APP_API_TOKEN
`

const golangMainGo = `package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("ENCLAVE_APP_PORT")
	if port == "" {
		port = "7074"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from the enclave!")
	})

	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
`

const golangGoMod = `module github.com/OWNER/REPO

go 1.22
`

// --- Node.js template constants ---

const nodejsConfigTemplate = `# Enclave configuration
# Edit this file then run: enclave init

name: my-app                     # App name (used in stack name, EIF name)
version: dev                     # Build version
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
nix_image: nixos/nix:2.24.9      # Docker image for reproducible builds

# SDK coordinates for the enclave supervisor binary.
# The supervisor handles attestation, secrets, PCR extension, and signing
# middleware automatically. Your app is a plain HTTP server with zero SDK imports.
sdk:
  rev: ""                        # SDK git commit SHA (required)
  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)
  vendor_hash: ""                # Go vendor hash (required)

app:
  language: "nodejs"             # App language: go, nodejs, dotnet
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave.
  # Your app is a normal Node.js HTTP server that listens on ENCLAVE_APP_PORT (default 7074).
  # Secrets are passed as environment variables. No SDK imports needed.
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_vendor_hash: ""            # npm deps hash (required)
  binary_name: ""                # Package name from package.json (defaults to 'name')

  # Environment variables baked into the EIF.
  # Template vars: {{region}}, {{prefix}}, {{version}}
  env:
    # MY_APP_DATA_DIR: /app/data
    # MY_APP_REGION: "{{region}}"

# Secrets managed by KMS inside the enclave.
# Each secret is generated as 32 random bytes, encrypted with KMS,
# stored in SSM, and decrypted at boot via attestation.
# The decrypted value (hex-encoded) is set as the specified env var.
secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
  # - name: api_token
  #   env_var: APP_API_TOKEN
`

const nodejsIndexJs = `const http = require("http");

const port = process.env.ENCLAVE_APP_PORT || "7074";

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Hello from the enclave!\n");
});

server.listen(port, () => {
  console.log(` + "`listening on :${port}`" + `);
});
`

const nodejsPackageJson = `{
  "name": "my-enclave-app",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  }
}
`

const nodejsPackageLockJson = `{
  "name": "my-enclave-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "my-enclave-app",
      "version": "1.0.0"
    }
  }
}
`

// --- README templates ---

const templateReadmeGolang = `# My Enclave App

An application that runs inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) using the [Introspector Enclave](https://github.com/ArkLabsHQ/introspector-enclave) framework.

## Prerequisites

- Go 1.22+
- Docker
- [Nix](https://nixos.org/)
- AWS CLI v2
- AWS CDK CLI (` + "`npm install -g aws-cdk`" + `)
- jq

## Quick Start

### 1. Install the enclave CLI

` + "```sh" + `
go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest
` + "```" + `

### 2. Configure

Edit ` + "`enclave/enclave.yaml`" + `:

- Set ` + "`account`" + ` to your AWS account ID
- Set ` + "`name`" + ` to your app name
- Configure ` + "`secrets`" + ` as needed

### 3. Set up app hashes

` + "```sh" + `
enclave setup
` + "```" + `

This auto-detects your GitHub remote and computes all Nix hashes.

### 4. Build

` + "```sh" + `
enclave build
` + "```" + `

Produces a reproducible EIF image with deterministic PCR0 measurements.

### 5. Deploy

` + "```sh" + `
enclave deploy
` + "```" + `

Creates the full AWS stack: VPC, EC2, KMS key, IAM roles, and secrets.

### 6. Verify

` + "```sh" + `
enclave verify
` + "```" + `

Verifies the running enclave's attestation document matches your local build.

## Writing Your App

Your app is a plain Go HTTP server. No SDK imports needed.

- Listen on ` + "`ENCLAVE_APP_PORT`" + ` (default 7074)
- Read secrets from environment variables (e.g. ` + "`APP_SIGNING_KEY`" + `)
- The enclave supervisor handles TLS, attestation, and response signing

## Development Workflow

The enclave build fetches your app source from GitHub at the exact commit specified
in ` + "`enclave.yaml`" + `. Your code must be committed and pushed before building.

**After code changes (no new dependencies):**

` + "```sh" + `
git add -A && git commit -m "my changes" && git push
enclave update    # fast: updates nix_rev + nix_hash only
enclave build
` + "```" + `

**After dependency changes (go.mod / go.sum):**

` + "```sh" + `
git add -A && git commit -m "update deps" && git push
enclave setup     # full: recomputes all hashes including vendor hash
enclave build
` + "```" + `

See [Introspector Enclave documentation](https://github.com/ArkLabsHQ/introspector-enclave) for the full reference.
`

const templateReadmeNodejs = `# My Enclave App

An application that runs inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) using the [Introspector Enclave](https://github.com/ArkLabsHQ/introspector-enclave) framework.

## Prerequisites

- Node.js 22+
- Docker
- [Nix](https://nixos.org/)
- AWS CLI v2
- AWS CDK CLI (` + "`npm install -g aws-cdk`" + `)
- jq

## Quick Start

### 1. Install the enclave CLI

` + "```sh" + `
go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest
` + "```" + `

### 2. Configure

Edit ` + "`enclave/enclave.yaml`" + `:

- Set ` + "`account`" + ` to your AWS account ID
- Set ` + "`name`" + ` to your app name
- Configure ` + "`secrets`" + ` as needed

### 3. Set up app hashes

` + "```sh" + `
enclave setup --language nodejs
` + "```" + `

This auto-detects your GitHub remote and computes all Nix hashes (including npm deps hash).

### 4. Build

` + "```sh" + `
enclave build
` + "```" + `

Produces a reproducible EIF image with deterministic PCR0 measurements.

### 5. Deploy

` + "```sh" + `
enclave deploy
` + "```" + `

Creates the full AWS stack: VPC, EC2, KMS key, IAM roles, and secrets.

### 6. Verify

` + "```sh" + `
enclave verify
` + "```" + `

Verifies the running enclave's attestation document matches your local build.

## Writing Your App

Your app is a plain Node.js HTTP server. No SDK imports needed.

- Listen on ` + "`ENCLAVE_APP_PORT`" + ` (default 7074)
- Read secrets from environment variables (e.g. ` + "`APP_SIGNING_KEY`" + `)
- The enclave supervisor handles TLS, attestation, and response signing

## Development Workflow

The enclave build fetches your app source from GitHub at the exact commit specified
in ` + "`enclave.yaml`" + `. Your code must be committed and pushed before building.

**Important:** ` + "`package-lock.json`" + ` must be committed to your repository.
Nix requires it to compute reproducible dependency hashes.

**After code changes (no new dependencies):**

` + "```sh" + `
git add -A && git commit -m "my changes" && git push
enclave update    # fast: updates nix_rev + nix_hash only
enclave build
` + "```" + `

**After dependency changes (package.json):**

` + "```sh" + `
npm install                # updates package-lock.json
git add -A && git commit -m "update deps" && git push
enclave setup --language nodejs   # full: recomputes all hashes including npm deps hash
enclave build
` + "```" + `

See [Introspector Enclave documentation](https://github.com/ArkLabsHQ/introspector-enclave) for the full reference.
`

// --- .NET template constants ---

const dotnetConfigTemplate = `# Enclave configuration
# Edit this file then run: enclave init

name: my-app                     # App name (used in stack name, EIF name)
version: dev                     # Build version
region: us-east-1                # AWS region
account: ""                      # AWS account ID (required)
prefix: dev                      # Deployment prefix (stack = {prefix}Nitro{Name})
instance_type: m6i.xlarge        # EC2 instance type
nix_image: nixos/nix:2.24.9      # Docker image for reproducible builds

# SDK coordinates for the enclave supervisor binary.
# The supervisor handles attestation, secrets, PCR extension, and signing
# middleware automatically. Your app is a plain HTTP server with zero SDK imports.
sdk:
  rev: ""                        # SDK git commit SHA (required)
  hash: ""                       # Nix source hash: nix-prefetch-url --unpack (required)
  vendor_hash: ""                # Go vendor hash (required)

app:
  language: "dotnet"             # App language: go, nodejs, dotnet
  source: nix                    # "nix" = fetch from GitHub via Nix

  # GitHub coordinates for the app to run inside the enclave.
  # Your app is a normal .NET HTTP server that listens on ENCLAVE_APP_PORT (default 7074).
  # Secrets are passed as environment variables. No SDK imports needed.
  nix_owner: ""                  # GitHub owner (required)
  nix_repo: ""                   # GitHub repo name (required)
  nix_rev: ""                    # Git commit SHA (required)
  nix_hash: ""                   # Nix source hash: nix-prefetch-url --unpack (required)
  nix_project_file: "MyEnclaveApp.csproj"  # .csproj file to build (required)
  # NuGet deps: run 'enclave setup' to generate deps.json (used by flake.nix)
  binary_name: ""                # Output binary name (defaults to 'name')

  # Environment variables baked into the EIF.
  # Template vars: {{region}}, {{prefix}}, {{version}}
  env:
    # MY_APP_DATA_DIR: /app/data
    # MY_APP_REGION: "{{region}}"

# Secrets managed by KMS inside the enclave.
# Each secret is generated as 32 random bytes, encrypted with KMS,
# stored in SSM, and decrypted at boot via attestation.
# The decrypted value (hex-encoded) is set as the specified env var.
secrets:
  - name: signing_key
    env_var: APP_SIGNING_KEY
  # - name: api_token
  #   env_var: APP_API_TOKEN
`

const dotnetProgramCs = `var port = Environment.GetEnvironmentVariable("ENCLAVE_APP_PORT") ?? "7074";

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

var app = builder.Build();

app.MapGet("/", () => "Hello from the enclave!");

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

app.Run();
`

const dotnetCsproj = `<Project Sdk="Microsoft.NET.Sdk.Web">

  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <RuntimeIdentifier>linux-x64</RuntimeIdentifier>
    <SelfContained>true</SelfContained>

    <!-- Reproducible builds: deterministic output regardless of build machine -->
    <Deterministic>true</Deterministic>
    <ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>

    <!-- Optional: Native AOT for smaller binary and faster cold start.
         Uncomment if all your dependencies support AOT compilation.
         Not all NuGet packages are AOT-compatible (reflection-heavy libs may fail).
    <PublishAot>true</PublishAot>
    <StripSymbols>true</StripSymbols>
    -->
  </PropertyGroup>

</Project>
`

const dotnetNugetConfig = `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
`

const templateReadmeDotnet = `# My Enclave App

An application that runs inside an [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) using the [Introspector Enclave](https://github.com/ArkLabsHQ/introspector-enclave) framework.

## Prerequisites

- .NET 10 SDK
- Docker
- [Nix](https://nixos.org/)
- AWS CLI v2
- AWS CDK CLI (` + "`npm install -g aws-cdk`" + `)
- jq

## Quick Start

### 1. Install the enclave CLI

` + "```sh" + `
go install github.com/ArkLabsHQ/introspector-enclave/cmd/enclave@latest
` + "```" + `

### 2. Configure

Edit ` + "`enclave/enclave.yaml`" + `:

- Set ` + "`account`" + ` to your AWS account ID
- Set ` + "`name`" + ` to your app name
- Configure ` + "`secrets`" + ` as needed

### 3. Set up app hashes

` + "```sh" + `
enclave setup --language dotnet
` + "```" + `

This auto-detects your GitHub remote and computes all Nix hashes (including NuGet deps hash).

### 4. Build

` + "```sh" + `
enclave build
` + "```" + `

Produces a reproducible EIF image with deterministic PCR0 measurements.

### 5. Deploy

` + "```sh" + `
enclave deploy
` + "```" + `

Creates the full AWS stack: VPC, EC2, KMS key, IAM roles, and secrets.

### 6. Verify

` + "```sh" + `
enclave verify
` + "```" + `

Verifies the running enclave's attestation document matches your local build.

## Writing Your App

Your app is a plain .NET HTTP server. No SDK imports needed.

- Listen on ` + "`ENCLAVE_APP_PORT`" + ` (default 7074)
- Read secrets from environment variables (e.g. ` + "`APP_SIGNING_KEY`" + `)
- The enclave supervisor handles TLS, attestation, and response signing

## Reproducible Builds

The template includes settings for deterministic builds:

- ` + "`<Deterministic>true</Deterministic>`" + ` eliminates timestamps from IL
- ` + "`<ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>`" + ` normalizes source paths
- NuGet dependencies are pinned via Nix deps hash
- The Nix sandbox ensures hermetic builds

## Development Workflow

The enclave build fetches your app source from GitHub at the exact commit specified
in ` + "`enclave.yaml`" + `. Your code must be committed and pushed before building.

**After code changes (no new dependencies):**

` + "```sh" + `
git add -A && git commit -m "my changes" && git push
enclave update    # fast: updates nix_rev + nix_hash only
enclave build
` + "```" + `

**After dependency changes (NuGet packages):**

` + "```sh" + `
dotnet restore
git add -A && git commit -m "update deps" && git push
enclave setup --language dotnet   # full: recomputes all hashes including NuGet deps hash
enclave build
` + "```" + `

See [Introspector Enclave documentation](https://github.com/ArkLabsHQ/introspector-enclave) for the full reference.
`
