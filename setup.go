package introspector_enclave

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

func setupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Auto-populate app nix hashes in enclave.yaml",
		Long: `Detects the GitHub owner/repo from git remote, computes nix_rev,
nix_hash, and nix_vendor_hash, and updates enclave/enclave.yaml.

Uses the local Nix installation for hash computation.
The app language is read from enclave.yaml (set via 'enclave init --language').

All hashes are computed from the local git repo — no fetch from GitHub.`,
		RunE: runSetup,
	}
	cmd.Flags().String("commit", "", "Git commit SHA to compute hashes for (required)")
	_ = cmd.MarkFlagRequired("commit")
	return cmd
}

func runSetup(cmd *cobra.Command, args []string) error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	// 1. Detect owner/repo from git remote.
	owner, repo, err := detectGitRemote(root)
	if err != nil {
		return err
	}
	fmt.Printf("[setup] Detected repo: %s/%s\n", owner, repo)

	// 2. Resolve commit SHA (from --commit flag or HEAD).
	rev, err := resolveCommit(cmd, root)
	if err != nil {
		return err
	}
	commitFlag, _ := cmd.Flags().GetString("commit")
	if commitFlag != "" {
		fmt.Printf("[setup] Using commit: %s\n", rev)
	} else {
		fmt.Printf("[setup] HEAD commit: %s\n", rev)
	}

	// 3. Load config for nix image and sub-packages.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Read language from enclave.yaml (set via 'enclave init --language').
	language := cfg.App.Language
	if language == "" {
		language = "go"
	}
	fmt.Printf("[setup] Language: %s\n", language)

	// Rewrite flake.nix to match the language.
	for _, f := range getFrameworkFiles(language) {
		if f.RelPath == "flake.nix" {
			destPath := filepath.Join(root, f.RelPath)
			if err := os.WriteFile(destPath, []byte(f.Content), f.Mode); err != nil {
				return fmt.Errorf("write %s: %w", f.RelPath, err)
			}
			fmt.Printf("[setup] Wrote %s for %s\n", f.RelPath, language)
			break
		}
	}

	// Generate flake.lock to pin all input revisions for reproducible builds.
	fmt.Println("[setup] Generating flake.lock...")
	lockCmd := exec.Command("nix", "flake", "lock",
		"--extra-experimental-features", "nix-command flakes",
	)
	lockCmd.Dir = root
	lockCmd.Stdout = os.Stdout
	lockCmd.Stderr = os.Stderr
	if err := lockCmd.Run(); err != nil {
		fmt.Printf("[setup] Warning: could not generate flake.lock: %v\n", err)
		fmt.Println("[setup] Run 'nix flake lock' manually and commit flake.lock for reproducible builds.")
	} else {
		fmt.Println("[setup] Generated flake.lock — commit this file for reproducible builds.")
	}

	subPackages := cfg.App.NixSubPackages
	if len(subPackages) == 0 {
		subPackages = []string{"."}
	}

	var nixHash, vendorHash string
	var vendorErr error

	// Check nix is available.
	if _, err := exec.LookPath("nix"); err != nil {
		return fmt.Errorf("nix is required but not found in PATH; install from https://nixos.org")
	}

	// 3. Compute nix source hash.
	fmt.Println("[setup] Computing nix source hash (local)...")
	nixHash, err = computeNixHash(root, rev)
	if err != nil {
		return err
	}
	fmt.Printf("[setup] nix_hash: %s\n", nixHash)

	// 4. Write nix_rev, nix_hash, owner, repo to enclave.yaml first
	//    so the flake's vendor-hash-check can fetch the correct source.
	{
		cfgPath := filepath.Join(root, configFile)
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", configFile, err)
		}
		content := string(data)
		content = replaceYAMLValue(content, "nix_rev", rev)
		content = replaceYAMLValue(content, "nix_hash", nixHash)
		content = replaceYAMLValue(content, "nix_owner", owner)
		content = replaceYAMLValue(content, "nix_repo", repo)
		if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", configFile, err)
		}
	}

	// 5. Compute vendor/deps hash via trial nix build.
	if language == "dotnet" {
		fmt.Println("[setup] Generating NuGet deps.json...")
		vendorErr = generateDotnetDeps(root)
		if vendorErr == nil {
			vendorHash = "deps.json"
		}
	} else {
		fmt.Println("[setup] Computing deps hash (local trial nix build)...")
		vendorHash, vendorErr = computeVendorHash(root, subPackages, language)
	}

	if vendorErr != nil {
		fmt.Printf("[setup] Warning: could not compute vendor hash: %v\n", vendorErr)
		if language == "dotnet" {
			fmt.Println("[setup] Will update other fields; you'll need to generate deps.json manually.")
		} else {
			fmt.Println("[setup] Will update other fields; you'll need to fill nix_vendor_hash manually.")
		}
	} else if language == "dotnet" {
		fmt.Println("[setup] deps.json generated successfully")
	} else {
		fmt.Printf("[setup] nix_vendor_hash: %s\n", vendorHash)
	}

	// 5. Update enclave.yaml preserving comments.
	cfgPath := filepath.Join(root, configFile)
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", configFile, err)
	}

	content := string(data)
	content = replaceYAMLValue(content, "nix_owner", owner)
	content = replaceYAMLValue(content, "nix_repo", repo)
	content = replaceYAMLValue(content, "nix_rev", rev)
	if nixHash != "" {
		content = replaceYAMLValue(content, "nix_hash", nixHash)
	}
	// For dotnet, deps are in deps.json not nix_vendor_hash — skip updating that field.
	if vendorHash != "" && language != "dotnet" {
		content = replaceYAMLValue(content, "nix_vendor_hash", vendorHash)
	}

	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write %s: %w", configFile, err)
	}

	fmt.Println()
	fmt.Printf("[setup] Updated %s\n", configFile)
	if vendorHash == "" {
		fmt.Println()
		if language == "dotnet" {
			fmt.Println("Warning: deps.json was not generated.")
			fmt.Println("To generate it manually:")
			fmt.Println("  1. Create an empty deps.json: echo '[]' > deps.json")
			fmt.Println("  2. Run: nix build --impure --expr 'let pkgs = import <nixpkgs> {}; in (pkgs.buildDotnetModule { pname = \"app\"; version = \"0.0.1\"; src = ./.; dotnet-sdk = pkgs.dotnetCorePackages.sdk_10_0_1xx; dotnet-runtime = pkgs.dotnetCorePackages.aspnetcore_10_0; nugetDeps = ./deps.json; doCheck = false; }).passthru.fetch-deps'")
			fmt.Println("  3. Run the resulting script: ./result deps.json")
			fmt.Println("  4. The generated deps.json should be in your project root (next to flake.nix)")
		} else {
			fmt.Println("Warning: nix_vendor_hash is still empty.")
			fmt.Println("To compute it manually:")
			fmt.Println("  1. Run 'nix build' with vendorHash = \"\" in your flake")
			fmt.Println("  2. Copy the 'got: sha256-...' hash from the error output")
			fmt.Println("  3. Paste it as nix_vendor_hash in enclave/enclave.yaml")
		}
	}
	fmt.Println()
	fmt.Println("Next: enclave build")
	return nil
}

// computeHashesDocker runs nix hash + vendor hash computation inside a Docker
// container using the same nixos image as 'enclave build'.
// Results are written to .enclave-setup-result in the mounted directory.
func computeHashesDocker(root, rev string, subPackages []string, nixImage string, language string) (nixHash, vendorHash string, err error) {
	resultFile := ".enclave-setup-result"

	trialBuildExpr := buildTrialExpr(language, subPackages, false)

	// Shell script that runs inside the container.
	// Writes results to a file in the mounted volume so the host can read them.
	script := fmt.Sprintf(`set -e
git config --global --add safe.directory /src

# Compute source hash from local git archive.
TMPDIR=$(mktemp -d)
git archive --format=tar.gz --prefix=source/ %s | tar xz -C "$TMPDIR"
SOURCE_HASH=$(nix --extra-experimental-features nix-command hash path "$TMPDIR/source")
rm -rf "$TMPDIR"
echo "nix_hash=$SOURCE_HASH" > /src/%s

# Compute deps hash via trial build.
# Use --log-format raw to strip ANSI escape codes.
nix build --impure --no-link \
  --extra-experimental-features 'nix-command flakes' \
  --log-format raw \
  --expr '%s' > /tmp/vendor.log 2>&1 || true
# grep is available in the Nix image; extract "got: sha256-..." line.
VENDOR_LINE=$(grep 'got:' /tmp/vendor.log | grep -o 'sha256-[^[:space:]]*' || true)
VENDOR_HASH="$VENDOR_LINE"
if [ -n "$VENDOR_HASH" ]; then
  echo "vendor_hash=$VENDOR_HASH" >> /src/%s
else
  cat /tmp/vendor.log >&2
  echo "vendor_err=Could not extract deps hash" >> /src/%s
fi
`, rev, resultFile, trialBuildExpr, resultFile, resultFile)

	// Run inside Docker using the existing runContainer function.
	if err := runContainer(context.Background(), nixImage, script, root, "/src", nil); err != nil {
		return "", "", fmt.Errorf("docker setup failed: %w", err)
	}

	// Read results from the file written by the container.
	resultPath := filepath.Join(root, resultFile)
	defer func() { _ = os.Remove(resultPath) }()

	data, err := os.ReadFile(resultPath)
	if err != nil {
		return "", "", fmt.Errorf("read setup results: %w", err)
	}

	results := string(data)
	for _, line := range strings.Split(results, "\n") {
		if strings.HasPrefix(line, "nix_hash=") {
			nixHash = strings.TrimPrefix(line, "nix_hash=")
		}
		if strings.HasPrefix(line, "vendor_hash=") {
			vendorHash = strings.TrimPrefix(line, "vendor_hash=")
		}
	}

	if nixHash == "" {
		return "", "", fmt.Errorf("could not compute nix_hash in Docker container")
	}

	if vendorHash == "" {
		return nixHash, "", fmt.Errorf("could not extract vendor hash from Docker trial build")
	}

	return nixHash, vendorHash, nil
}

// detectGitRemote parses the origin remote URL to extract GitHub owner and repo.
func detectGitRemote(root string) (owner, repo string, err error) {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("cannot detect git remote: %w (make sure you are in a git repo with an 'origin' remote)", err)
	}

	remoteURL := strings.TrimSpace(string(out))
	return parseGitRemoteURL(remoteURL)
}

// parseGitRemoteURL extracts owner/repo from SSH or HTTPS git URLs.
func parseGitRemoteURL(rawURL string) (owner, repo string, err error) {
	// SSH: git@github.com:Owner/Repo.git
	if strings.HasPrefix(rawURL, "git@") {
		parts := strings.SplitN(rawURL, ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("cannot parse SSH remote URL: %s", rawURL)
		}
		path := strings.TrimSuffix(parts[1], ".git")
		segments := strings.SplitN(path, "/", 2)
		if len(segments) != 2 {
			return "", "", fmt.Errorf("cannot parse owner/repo from remote URL: %s", rawURL)
		}
		return segments[0], segments[1], nil
	}

	// HTTPS: https://github.com/Owner/Repo.git
	trimmed := rawURL
	trimmed = strings.TrimPrefix(trimmed, "https://")
	trimmed = strings.TrimPrefix(trimmed, "http://")
	trimmed = strings.TrimSuffix(trimmed, ".git")

	// Split on / — expect host/owner/repo
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("cannot parse owner/repo from remote URL: %s", rawURL)
	}
	// parts[0] = "github.com", parts[1] = owner, parts[2] = repo
	return parts[1], parts[2], nil
}

// gitRevParseHEAD returns the full SHA of HEAD.
func gitRevParseHEAD(root string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitRevParseCommit validates and normalizes a commitish to a full SHA.
func gitRevParseCommit(root, commitish string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--verify", commitish+"^{commit}")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("commit %q not found in local repo: %w", commitish, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// resolveCommit returns the commit SHA from --commit flag or HEAD.
func resolveCommit(cmd *cobra.Command, root string) (string, error) {
	commitFlag, _ := cmd.Flags().GetString("commit")
	if commitFlag != "" {
		return gitRevParseCommit(root, commitFlag)
	}
	return gitRevParseHEAD(root)
}

// computeNixHash computes the SRI hash that matches Nix's fetchFromGitHub
// by creating a git archive locally and hashing it with nix hash path.
func computeNixHash(root string, rev string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "enclave-setup-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// git archive --format=tar.gz --prefix=source/ <rev> | tar xz -C tmpDir
	archiveCmd := exec.Command("git", "archive", "--format=tar.gz", "--prefix=source/", rev)
	archiveCmd.Dir = root

	tarCmd := exec.Command("tar", "xz", "-C", tmpDir)
	tarCmd.Stdin, err = archiveCmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("pipe setup: %w", err)
	}

	if err := tarCmd.Start(); err != nil {
		return "", fmt.Errorf("start tar: %w", err)
	}
	if err := archiveCmd.Run(); err != nil {
		return "", fmt.Errorf("git archive: %w", err)
	}
	if err := tarCmd.Wait(); err != nil {
		return "", fmt.Errorf("tar extract: %w", err)
	}

	// nix hash path tmpDir/source
	hashCmd := exec.Command("nix", "hash", "path", filepath.Join(tmpDir, "source"))
	out, err := hashCmd.Output()
	if err != nil {
		return "", fmt.Errorf("nix hash path: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

// buildTrialExpr returns a Nix expression for a trial build with an empty deps
// hash. When built, Nix will fail and print the expected hash in a "got:" line.
// If escaped is true, quotes are backslash-escaped (for embedding in shell scripts).
// If nixpkgsRev is non-empty, it pins nixpkgs to that exact commit for reproducibility.
func buildTrialExpr(language string, subPackages []string, escaped bool, nixpkgsRev ...string) string {
	q := `"`
	if escaped {
		q = `\"`
	}
	nixpkgsImport := `let pkgs = import <nixpkgs> {}; in`

	switch language {
	case "nodejs":
		return nixpkgsImport + ` pkgs.buildNpmPackage {
    pname = "app"; version = "0.0.1"; src = ./.;
    npmDepsHash = ""; dontNpmBuild = true; doCheck = false;
  }`
	case "rust":
		return nixpkgsImport + ` pkgs.rustPlatform.buildRustPackage {
    pname = "app"; version = "0.0.1"; src = ./.;
    cargoHash = ""; doCheck = false;
  }`
	default: // "go"
		var nixPkgs []string
		for _, p := range subPackages {
			nixPkgs = append(nixPkgs, q+p+q)
		}
		nixSubPkgs := "[ " + strings.Join(nixPkgs, " ") + " ]"
		return fmt.Sprintf(nixpkgsImport+` pkgs.buildGoModule {
    pname = "app"; version = "0.0.1"; src = ./.;
    subPackages = %s; vendorHash = ""; proxyVendor = true;
    CGO_ENABLED = "0"; doCheck = false;
  }`, nixSubPkgs)
	}
}

// computeVendorHash discovers the correct deps hash by running a trial build
// using the project's flake. The flake exposes a `vendor-hash-check` package
// that builds the app's Go modules with vendorHash = "", which always fails
// and prints the correct hash. This ensures the hash matches the exact nixpkgs
// pin in flake.lock — same Go version as `enclave build`.
func computeVendorHash(root string, subPackages []string, language string) (string, error) {
	// Generate build-config.json so the flake can read the app config.
	cfg, err := loadConfig()
	if err != nil {
		return "", fmt.Errorf("load config for trial build: %w", err)
	}
	if err := generateBuildConfig(cfg, root); err != nil {
		return "", fmt.Errorf("generate build-config.json: %w", err)
	}

	// Ensure files are git-tracked (flakes only see tracked files).
	ensureGitTracked(root, "flake.nix", "enclave/build-config.json", "enclave/start.sh", "enclave/enclave.yaml")

	configPath := filepath.Join(root, "enclave", "build-config.json")
	absConfigPath, _ := filepath.Abs(configPath)

	cmd := exec.Command("nix", "build",
		"--impure",
		"--no-link",
		"--extra-experimental-features", "nix-command flakes",
		".#vendor-hash-check",
	)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "BUILD_CONFIG_PATH="+absConfigPath)

	// We expect this to fail — we want the error output with the expected hash.
	// Capture both stdout and stderr since Nix may print the hash on either.
	var output bytes.Buffer
	cmd.Stderr = &output
	cmd.Stdout = &output

	_ = cmd.Run() // intentionally ignore error — we expect failure

	// Parse "got:    sha256-..." from combined output.
	outputStr := output.String()
	re := regexp.MustCompile(`got:\s+(sha256-\S+)`)
	matches := re.FindStringSubmatch(outputStr)
	if len(matches) < 2 {
		fmt.Fprintf(os.Stderr, "\n[setup] Trial build output:\n%s\n", outputStr)
		return "", fmt.Errorf("could not extract vendor hash from trial build output")
	}

	return matches[1], nil
}

// generateDotnetDeps generates a deps.json file for a .NET project using
// nix's fetch-deps mechanism. Unlike Go/Node, dotnet doesn't use a hash —
// it needs a JSON file listing all NuGet packages and their hashes.
func generateDotnetDeps(root string) error {
	// Seed an empty deps.json so nugetDeps = ./deps.json is a valid path.
	// Without this, nugetDeps defaults to null and fetch-deps isn't generated.
	depsPath := filepath.Join(root, "deps.json")
	if err := os.WriteFile(depsPath, []byte("[]\n"), 0644); err != nil {
		return fmt.Errorf("write seed deps.json: %w", err)
	}

	// Step 1: Build the fetch-deps script via passthru.
	expr := `let pkgs = import <nixpkgs> {}; in (pkgs.buildDotnetModule {
    pname = "app"; version = "0.0.1"; src = ./.;
    dotnet-sdk = pkgs.dotnetCorePackages.sdk_10_0_1xx;
    dotnet-runtime = pkgs.dotnetCorePackages.aspnetcore_10_0;
    nugetDeps = ./deps.json;
    doCheck = false;
  }).passthru.fetch-deps`

	cmd := exec.Command("nix", "build",
		"--impure",
		"--extra-experimental-features", "nix-command flakes",
		"--expr", expr,
	)
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build fetch-deps script: %w", err)
	}

	// Step 2: Run the fetch-deps script to regenerate deps.json with real deps.
	fetchCmd := exec.Command("./result", depsPath)
	fetchCmd.Dir = root
	fetchCmd.Stdout = os.Stdout
	fetchCmd.Stderr = os.Stderr

	if err := fetchCmd.Run(); err != nil {
		return fmt.Errorf("run fetch-deps script: %w", err)
	}

	// Verify deps.json was created.
	if _, err := os.Stat(depsPath); err != nil {
		return fmt.Errorf("deps.json not created: %w", err)
	}

	fmt.Printf("[setup] Generated %s\n", depsPath)
	return nil
}

// computeHashesDotnetDocker computes the nix source hash and generates deps.json
// for a .NET project inside a Docker container.
func computeHashesDotnetDocker(root, rev, nixImage string) (nixHash string, err error) {
	resultFile := ".enclave-setup-result"

	script := fmt.Sprintf(`set -e
git config --global --add safe.directory /src

# Compute source hash from local git archive.
TMPDIR=$(mktemp -d)
git archive --format=tar.gz --prefix=source/ %s | tar xz -C "$TMPDIR"
SOURCE_HASH=$(nix --extra-experimental-features nix-command hash path "$TMPDIR/source")
rm -rf "$TMPDIR"
echo "nix_hash=$SOURCE_HASH" > /src/%s

# Seed empty deps.json so nugetDeps is a path (enables fetch-deps passthru)
echo '[]' > /src/deps.json

# Generate deps.json via fetch-deps
nix build --impure \
  --extra-experimental-features 'nix-command flakes' \
  --expr 'let pkgs = import <nixpkgs> {}; in (pkgs.buildDotnetModule {
    pname = "app"; version = "0.0.1"; src = ./.;
    dotnet-sdk = pkgs.dotnetCorePackages.sdk_10_0_1xx;
    dotnet-runtime = pkgs.dotnetCorePackages.aspnetcore_10_0;
    nugetDeps = ./deps.json;
    doCheck = false;
  }).passthru.fetch-deps' 2>&1 || true

if [ -x ./result ]; then
  ./result /src/deps.json 2>&1
  if [ -f /src/deps.json ]; then
    echo "deps_ok=true" >> /src/%s
  else
    echo "deps_err=deps.json not generated" >> /src/%s
  fi
else
  echo "deps_err=fetch-deps script not built" >> /src/%s
fi
`, rev, resultFile, resultFile, resultFile, resultFile)

	if err := runContainer(context.Background(), nixImage, script, root, "/src", nil); err != nil {
		return "", fmt.Errorf("docker setup failed: %w", err)
	}

	resultPath := filepath.Join(root, resultFile)
	defer func() { _ = os.Remove(resultPath) }()

	data, err := os.ReadFile(resultPath)
	if err != nil {
		return "", fmt.Errorf("read setup results: %w", err)
	}

	var depsOK bool
	results := string(data)
	for _, line := range strings.Split(results, "\n") {
		if strings.HasPrefix(line, "nix_hash=") {
			nixHash = strings.TrimPrefix(line, "nix_hash=")
		}
		if strings.HasPrefix(line, "deps_ok=") {
			depsOK = true
		}
	}

	if nixHash == "" {
		return "", fmt.Errorf("could not compute nix_hash in Docker container")
	}
	if nixHash != "" {
		fmt.Printf("[setup] nix_hash: %s\n", nixHash)
	}
	if !depsOK {
		return nixHash, fmt.Errorf("could not generate deps.json in Docker container")
	}

	return nixHash, nil
}

// replaceYAMLValue replaces the value of a YAML key in-place, preserving
// the rest of the line (indentation, inline comments).
// Matches patterns like:  nix_owner: ""  or  nix_owner: "some-value"
// and replaces with:      nix_owner: "<newValue>"
func replaceYAMLValue(content, key, newValue string) string {
	// Match:  key: "anything"  (with optional surrounding whitespace)
	// Also match:  key: ""  (empty value)
	pattern := regexp.MustCompile(`(` + regexp.QuoteMeta(key) + `:\s*)"[^"]*"`)
	return pattern.ReplaceAllString(content, `${1}"`+newValue+`"`)
}
