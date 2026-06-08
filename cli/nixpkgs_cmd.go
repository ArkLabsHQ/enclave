package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// nixpkgsBranch is the nixpkgs branch tracked by `enclave nixpkgs pin`.
const nixpkgsBranch = "nixos-25.11"

func nixpkgsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nixpkgs",
		Short: "Manage the pinned nixpkgs commit for reproducible builds",
	}
	cmd.AddCommand(nixpkgsPinCmd())
	return cmd
}

func nixpkgsPinCmd() *cobra.Command {
	var checkOnly bool
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Pin nixpkgs to the current nixos-25.11 tip",
		Long: `Fetches the current tip of nixos-25.11, computes its SRI hash via
nix-prefetch-url, and writes both into:

  enclave/enclave.yaml  →  nix.nixpkgs_rev + nix.nixpkgs_hash
  enclave/flake.nix     →  nixpkgs.url = "github:NixOS/nixpkgs/<sha>"

After running, commit both files. Subsequent builds use the pinned commit
so the derivation graph — and therefore PCR0 — stays byte-identical until
you deliberately bump the pin.

The framework already ships a pinned SHA as its default, so this command
is only needed when you want to upgrade to a newer nixpkgs commit.

Use --check to validate the existing pin without any network access.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if checkOnly {
				return runPinCheck(cfg)
			}
			return runPinLatest()
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "Validate the existing pin without fetching (no network)")
	return cmd
}

func runPinCheck(cfg *Config) error {
	if cfg.Nix.NixpkgsRev == "" {
		return fmt.Errorf("no pin set — nix.nixpkgs_rev is empty in enclave.yaml (run `enclave nixpkgs pin` to create one)")
	}
	if !commitSHARegex.MatchString(cfg.Nix.NixpkgsRev) {
		return fmt.Errorf("nix.nixpkgs_rev %q is not a 40-char hex commit SHA", cfg.Nix.NixpkgsRev)
	}
	if !sriSha256Regex.MatchString(cfg.Nix.NixpkgsHash) {
		return fmt.Errorf("nix.nixpkgs_hash %q must be SRI-formatted sha256 ('sha256-' + 43 base64 chars + '=')", cfg.Nix.NixpkgsHash)
	}
	fmt.Printf("nixpkgs pin OK: %s (%s)\n", cfg.Nix.NixpkgsRev, cfg.Nix.NixpkgsHash)
	return nil
}

func runPinLatest() error {
	branch := nixpkgsBranch
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
		return "", fmt.Errorf("`git` not found on PATH — install git to use `enclave nixpkgs pin`")
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
	if _, err := exec.LookPath("nix-prefetch-url"); err != nil {
		return "", fmt.Errorf("`nix-prefetch-url` not on PATH — install Nix (https://nixos.org/download) to compute the SRI hash")
	}
	url := fmt.Sprintf("https://github.com/NixOS/nixpkgs/archive/%s.tar.gz", rev)
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
	// Anchored to the canonical 2-space indent under `nix:` so unrelated
	// fields elsewhere in the yaml can't accidentally match.
	nixpkgsRevYamlRegex  = regexp.MustCompile(`(?m)^(  nixpkgs_rev:\s*).*$`)
	nixpkgsHashYamlRegex = regexp.MustCompile(`(?m)^(  nixpkgs_hash:\s*).*$`)
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

	hasRev := nixpkgsRevYamlRegex.MatchString(content)
	hasHash := nixpkgsHashYamlRegex.MatchString(content)

	switch {
	case hasRev && hasHash:
		content = nixpkgsRevYamlRegex.ReplaceAllString(content, revRepl)
		content = nixpkgsHashYamlRegex.ReplaceAllString(content, hashRepl)
	case hasRev:
		content = nixpkgsRevYamlRegex.ReplaceAllString(content, revRepl)
		content = insertUnderNixBlock(content, fmt.Sprintf("  nixpkgs_hash: %q", hash))
	case hasHash:
		content = nixpkgsHashYamlRegex.ReplaceAllString(content, hashRepl)
		content = insertUnderNixBlock(content, fmt.Sprintf("  nixpkgs_rev:  %q", rev))
	default:
		// Neither field exists — insert both in one replacement to avoid
		// the double-call clobber bug (each call matches the same `nix:` line).
		content = insertUnderNixBlock(content, fmt.Sprintf("  nixpkgs_rev:  %q\n  nixpkgs_hash: %q", rev, hash))
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// insertUnderNixBlock inserts a line (or block of lines) immediately after
// the `nix:` header. Caller guarantees the nix: block exists.
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
