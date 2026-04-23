package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseGitRemoteURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			name:      "SSH",
			url:       "git@github.com:ArkLabsHQ/introspector-enclave.git",
			wantOwner: "ArkLabsHQ",
			wantRepo:  "introspector-enclave",
		},
		{
			name:      "HTTPS with .git",
			url:       "https://github.com/ArkLabsHQ/introspector-enclave.git",
			wantOwner: "ArkLabsHQ",
			wantRepo:  "introspector-enclave",
		},
		{
			name:      "HTTPS without .git",
			url:       "https://github.com/MyOrg/MyRepo",
			wantOwner: "MyOrg",
			wantRepo:  "MyRepo",
		},
		{
			name:      "HTTP",
			url:       "http://github.com/Owner/Repo.git",
			wantOwner: "Owner",
			wantRepo:  "Repo",
		},
		{
			name:    "invalid SSH missing colon",
			url:     "git@github.com/Owner/Repo",
			wantErr: true,
		},
		{
			name:    "invalid no path",
			url:     "https://github.com",
			wantErr: true,
		},
		{
			name:    "invalid single segment",
			url:     "https://github.com/onlyone",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, err := parseGitRemoteURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

func TestReplaceYAMLValue(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		key      string
		newValue string
		want     string
	}{
		{
			name:     "simple replacement",
			content:  `nix_rev: "oldvalue"`,
			key:      "nix_rev",
			newValue: "newvalue",
			want:     `nix_rev: "newvalue"`,
		},
		{
			name:     "empty to value",
			content:  `nix_hash: ""`,
			key:      "nix_hash",
			newValue: "sha256-abc",
			want:     `nix_hash: "sha256-abc"`,
		},
		{
			name:     "preserves surrounding content",
			content:  "name: \"myapp\"\nnix_rev: \"old\"\nregion: \"us-east-1\"",
			key:      "nix_rev",
			newValue: "new",
			want:     "name: \"myapp\"\nnix_rev: \"new\"\nregion: \"us-east-1\"",
		},
		{
			name:     "no match leaves unchanged",
			content:  `nix_rev: "old"`,
			key:      "nonexistent",
			newValue: "new",
			want:     `nix_rev: "old"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replaceYAMLValue(tt.content, tt.key, tt.newValue)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestComputeNixHash_MonorepoUsesRepoRoot guards against the regression
// where `git archive` was run with cwd set to the enclave.yaml directory.
// In a monorepo layout (git root != enclave config dir) that caused
// `git archive` to archive only the subtree, producing a hash that did
// not match what fetchFromGitHub computes for the full repo tarball.
//
// The fix resolves `git rev-parse --show-toplevel` and uses that as cwd.
//
// This test creates a repo with the enclave config in a subdirectory,
// computes the hash via the function-under-test, and compares it to the
// hash of the full repo archive. They must match.
func TestComputeNixHash_MonorepoUsesRepoRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("nix"); err != nil {
		t.Skip("nix not available")
	}
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not available")
	}

	repo := t.TempDir()

	// Minimal repo with a top-level file AND a subdirectory containing
	// enclave.yaml (the monorepo shape that previously triggered the bug).
	if err := os.WriteFile(filepath.Join(repo, "top.txt"), []byte("repo-root-content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "server", "enclave")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "enclave.yaml"), []byte("name: test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runIn := func(dir, name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	runIn(repo, "git", "init", "-q")
	runIn(repo, "git", "-c", "user.email=t@t", "-c", "user.name=T", "add", ".")
	runIn(repo, "git", "-c", "user.email=t@t", "-c", "user.name=T", "commit", "-q", "-m", "init")

	revOut, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	rev := strings.TrimSpace(string(revOut))

	// Simulate the buggy caller: pass the subdirectory (where enclave.yaml
	// lives) as the "root" argument. The fix should still produce the
	// full-repo hash by resolving the git top-level internally.
	got, err := computeNixHash(filepath.Join(repo, "server"), rev)
	if err != nil {
		t.Fatalf("computeNixHash: %v", err)
	}

	// Expected = hash of the full repo via git archive run at the git top.
	expTmp := t.TempDir()
	archive := exec.Command("git", "archive", "--format=tar.gz", "--prefix=source/", rev)
	archive.Dir = repo
	extract := exec.Command("tar", "xz", "-C", expTmp)
	extract.Stdin, err = archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := extract.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatal(err)
	}
	if err := extract.Wait(); err != nil {
		t.Fatal(err)
	}
	wantOut, err := exec.Command("nix", "hash", "path", filepath.Join(expTmp, "source")).Output()
	if err != nil {
		t.Fatalf("nix hash path: %v", err)
	}
	want := strings.TrimSpace(string(wantOut))

	if got != want {
		t.Errorf("computeNixHash from subdir = %q, want full-repo hash %q", got, want)
	}

	// Sanity check: the subtree-only hash must DIFFER from the full-repo hash
	// (otherwise this test can't detect the regression).
	subTmp := t.TempDir()
	subArchive := exec.Command("git", "archive", "--format=tar.gz", "--prefix=source/", rev)
	subArchive.Dir = filepath.Join(repo, "server")
	subExtract := exec.Command("tar", "xz", "-C", subTmp)
	subExtract.Stdin, err = subArchive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := subExtract.Start(); err != nil {
		t.Fatal(err)
	}
	if err := subArchive.Run(); err != nil {
		t.Fatal(err)
	}
	if err := subExtract.Wait(); err != nil {
		t.Fatal(err)
	}
	subHashOut, err := exec.Command("nix", "hash", "path", filepath.Join(subTmp, "source")).Output()
	if err != nil {
		t.Fatalf("nix hash path (subtree): %v", err)
	}
	subHash := strings.TrimSpace(string(subHashOut))
	if subHash == want {
		t.Fatal("test setup is broken: subtree hash equals full-repo hash, cannot detect regression")
	}
}
