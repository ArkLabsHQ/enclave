package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

const defaultNixpkgsBranch = "nixos-25.11"

func nixpkgsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nixpkgs",
		Short: "Manage the pinned nixpkgs commit for reproducible builds",
		Long: `Pin the nixpkgs revision used by the flake template to a specific commit.

A pinned commit guarantees the derivation graph is byte-identical across
builds — so the EIF stays reproducible even when the nixpkgs branch tip
moves upstream (security patches, package updates).

Use 'enclave nixpkgs pin --latest' to fetch the current branch tip and
write it to enclave.yaml + enclave/flake.nix. Use 'enclave nixpkgs pin --check'
to validate the existing pin without bumping it.`,
	}
	cmd.AddCommand(nixpkgsPinCmd())
	return cmd
}

func nixpkgsPinCmd() *cobra.Command {
	var latest bool
	var checkOnly bool
	var branch string
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Pin nixpkgs to a specific commit for byte-identical EIFs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !latest && !checkOnly {
				return fmt.Errorf("specify one of --latest or --check")
			}
			if latest && checkOnly {
				return fmt.Errorf("--latest and --check are mutually exclusive")
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if checkOnly {
				return runPinCheck(cfg)
			}
			return runPinLatest(branch)
		},
	}
	cmd.Flags().BoolVar(&latest, "latest", false, "Fetch the latest commit from --branch and pin to it (writes enclave.yaml + enclave/flake.nix)")
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Validate the existing pin without bumping (no network)")
	cmd.Flags().StringVar(&branch, "branch", defaultNixpkgsBranch, "nixpkgs branch to follow when --latest is set")
	return cmd
}

func runPinCheck(cfg *Config) error {
	if cfg.Nix.NixpkgsRev == "" {
		return fmt.Errorf("no pin set — nix.nixpkgs_rev is empty in enclave.yaml (run `enclave nixpkgs pin --latest` to create one)")
	}
	if !commitSHARegex.MatchString(cfg.Nix.NixpkgsRev) {
		return fmt.Errorf("nix.nixpkgs_rev %q is not a 40-char hex commit SHA", cfg.Nix.NixpkgsRev)
	}
	if !strings.HasPrefix(cfg.Nix.NixpkgsHash, "sha256-") {
		return fmt.Errorf("nix.nixpkgs_hash %q must start with 'sha256-' (SRI format)", cfg.Nix.NixpkgsHash)
	}
	fmt.Printf("nixpkgs pin OK: %s (%s)\n", cfg.Nix.NixpkgsRev, cfg.Nix.NixpkgsHash)
	return nil
}

func runPinLatest(branch string) error {
	root, err := findRepoRoot()
	if err != nil {
		return err
	}
	cfgPath := resolveConfigPath(root)

	fmt.Printf("[pin] Fetching tip of %s from github.com/NixOS/nixpkgs...\n", branch)
	rev, err := gitLsRemoteBranch("https://github.com/NixOS/nixpkgs.git", branch)
	if err != nil {
		return err
	}
	fmt.Printf("[pin] Tip is %s\n", rev)

	fmt.Printf("[pin] Computing SRI hash of the tarball (may take a minute)...\n")
	hash, err := prefetchNixpkgsHash(rev)
	if err != nil {
		return err
	}
	fmt.Printf("[pin] Hash is %s\n", hash)

	if err := updateNixpkgsInYaml(cfgPath, rev, hash); err != nil {
		return fmt.Errorf("update %s: %w", cfgPath, err)
	}
	flakePath := filepath.Join(filepath.Dir(cfgPath), "flake.nix")
	if _, err := os.Stat(flakePath); err == nil {
		if err := updateNixpkgsInFlake(flakePath, rev); err != nil {
			return fmt.Errorf("update %s: %w", flakePath, err)
		}
		fmt.Printf("[pin] Updated %s\n", flakePath)
	}

	fmt.Printf("[pin] Updated %s\n", cfgPath)
	fmt.Printf("[pin] Pinned nixpkgs to %s\n", rev)
	return nil
}

// gitLsRemoteBranch returns the commit SHA at the tip of the given branch.
// Shells out to `git ls-remote` since the alternative (hitting the GitHub
// API) needs auth for high-traffic users.
func gitLsRemoteBranch(repoURL, branch string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("`git` not found on PATH — install git to use `enclave nixpkgs pin --latest`")
	}
	out, err := exec.Command("git", "ls-remote", repoURL, "refs/heads/"+branch).Output()
	if err != nil {
		return "", fmt.Errorf("git ls-remote %s %s: %w", repoURL, branch, err)
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", fmt.Errorf("branch %q not found in %s", branch, repoURL)
	}
	sha := strings.Fields(line)[0]
	if !commitSHARegex.MatchString(sha) {
		return "", fmt.Errorf("git ls-remote returned malformed SHA %q", sha)
	}
	return sha, nil
}

// prefetchNixpkgsHash downloads the nixpkgs tarball for the given commit
// and returns the SRI hash of the unpacked contents. Uses `nix-prefetch-url
// --unpack` so the hash matches what fetchTarball produces in the flake.
func prefetchNixpkgsHash(rev string) (string, error) {
	url := fmt.Sprintf("https://github.com/NixOS/nixpkgs/archive/%s.tar.gz", rev)
	if _, err := exec.LookPath("nix-prefetch-url"); err == nil {
		out, err := exec.Command("nix-prefetch-url", "--unpack", "--type", "sha256", url).Output()
		if err != nil {
			return "", fmt.Errorf("nix-prefetch-url %s: %w (is Nix installed?)", url, err)
		}
		raw := strings.TrimSpace(string(out))
		sri, err := nixHashToSRI(raw)
		if err != nil {
			return "", fmt.Errorf("convert nix-prefetch-url output to SRI: %w", err)
		}
		return sri, nil
	}
	return prefetchNixpkgsHashOverHTTP(url)
}

// prefetchNixpkgsHashOverHTTP downloads the tarball and computes the SRI
// hash directly. Slower than nix-prefetch-url (no caching) and only matches
// the unpacked-tree hash if used with `fetchTarball` style fetchers; flake
// inputs use a different hashing scheme. Kept as a fallback for hint only.
func prefetchNixpkgsHashOverHTTP(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("http get %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http get %s: %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", fmt.Errorf("read tarball: %w", err)
	}
	return "", fmt.Errorf("`nix-prefetch-url` not on PATH — install Nix (https://nixos.org/download) to compute the SRI hash (tarball downloaded OK at %d bytes but the gzipped-byte hash is not what Nix wants)", h.Size())
}

// nixHashToSRI converts a `nix-prefetch-url` (legacy base32) or already-SRI
// hash string to the SRI form Nix expects in flake inputs.
func nixHashToSRI(raw string) (string, error) {
	if strings.HasPrefix(raw, "sha256-") {
		return raw, nil
	}
	if _, err := exec.LookPath("nix"); err == nil {
		out, err := exec.Command("nix", "hash", "to-sri", "--type", "sha256", raw).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	if _, err := exec.LookPath("nix-hash"); err == nil {
		out, err := exec.Command("nix-hash", "--to-sri", "--type", "sha256", raw).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	decoded, err := decodeNixBase32(raw)
	if err != nil {
		return "", fmt.Errorf("hash %q is not SRI and could not be converted: %w", raw, err)
	}
	return "sha256-" + base64.StdEncoding.EncodeToString(decoded), nil
}

// nixBase32Alphabet is the alphabet used by Nix's legacy base32 hash encoding
// — see nixpkgs/lib/hash.nix. Lowercase, no 'e', 'o', 't', 'u'.
const nixBase32Alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

func decodeNixBase32(s string) ([]byte, error) {
	if len(s) != 52 {
		return nil, fmt.Errorf("expected 52-char base32 sha256 hash, got %d chars", len(s))
	}
	out := make([]byte, 32)
	for n := 0; n < 52; n++ {
		c := s[51-n]
		idx := strings.IndexByte(nixBase32Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base32 char %q at position %d", c, 51-n)
		}
		b := n * 5
		i := b / 8
		j := b % 8
		out[i] |= byte(idx) << j
		if i+1 < 32 {
			out[i+1] |= byte(idx) >> (8 - j)
		}
	}
	return out, nil
}

var (
	nixpkgsURLRegex = regexp.MustCompile(`(github:NixOS/nixpkgs/)[^"]+`)
	nixpkgsRevYamlRegex  = regexp.MustCompile(`(?m)^(\s*nixpkgs_rev:\s*).*$`)
	nixpkgsHashYamlRegex = regexp.MustCompile(`(?m)^(\s*nixpkgs_hash:\s*).*$`)
	nixBlockYamlRegex    = regexp.MustCompile(`(?m)^nix:\s*$`)
)

// updateNixpkgsInYaml writes rev + hash into the nix: block of enclave.yaml.
// If a nix: block already exists, the lines are updated in place; otherwise
// a minimal nix: block is appended. Preserves all surrounding comments.
func updateNixpkgsInYaml(path, rev, hash string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	if !nixBlockYamlRegex.MatchString(content) {
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += fmt.Sprintf("\nnix:\n  nixpkgs_rev:  %q\n  nixpkgs_hash: %q\n", rev, hash)
		return os.WriteFile(path, []byte(content), 0644)
	}

	revRepl := fmt.Sprintf(`${1}%q`, rev)
	hashRepl := fmt.Sprintf(`${1}%q`, hash)

	if nixpkgsRevYamlRegex.MatchString(content) {
		content = nixpkgsRevYamlRegex.ReplaceAllString(content, revRepl)
	} else {
		content = insertUnderNixBlock(content, fmt.Sprintf("  nixpkgs_rev:  %q", rev))
	}
	if nixpkgsHashYamlRegex.MatchString(content) {
		content = nixpkgsHashYamlRegex.ReplaceAllString(content, hashRepl)
	} else {
		content = insertUnderNixBlock(content, fmt.Sprintf("  nixpkgs_hash: %q", hash))
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// insertUnderNixBlock appends a line immediately after the `nix:` header,
// indented to match. Caller guarantees the nix: block exists.
func insertUnderNixBlock(content, line string) string {
	return nixBlockYamlRegex.ReplaceAllString(content, "nix:\n"+line)
}

// updateNixpkgsInFlake rewrites the nixpkgs.url line in flake.nix to point
// at the new commit SHA. No-op if no matching line exists.
func updateNixpkgsInFlake(path, rev string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated := nixpkgsURLRegex.ReplaceAllString(string(data), "${1}"+rev)
	if updated == string(data) {
		return nil
	}
	return os.WriteFile(path, []byte(updated), 0644)
}
