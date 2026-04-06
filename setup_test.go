package introspector_enclave

import (
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

func TestBuildTrialExpr(t *testing.T) {
	tests := []struct {
		name        string
		language    string
		subPackages []string
		wantContain string
	}{
		{
			name:        "go default",
			language:    "go",
			subPackages: []string{"."},
			wantContain: "buildGoModule",
		},
		{
			name:        "go multiple subpackages",
			language:    "go",
			subPackages: []string{"cmd/server", "cmd/worker"},
			wantContain: `"cmd/server"`,
		},
		{
			name:        "nodejs",
			language:    "nodejs",
			subPackages: nil,
			wantContain: "buildNpmPackage",
		},
		{
			name:        "rust",
			language:    "rust",
			subPackages: nil,
			wantContain: "buildRustPackage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := buildTrialExpr(tt.language, tt.subPackages, false)
			if !strings.Contains(expr, tt.wantContain) {
				t.Errorf("expression does not contain %q:\n%s", tt.wantContain, expr)
			}
		})
	}

	// Test escaped mode produces escaped quotes.
	escaped := buildTrialExpr("go", []string{"."}, true)
	if !strings.Contains(escaped, `\"."\"`) {
		// The escaped mode wraps subpackages in \"...\".
		// Check that escaped quotes are present.
		if !strings.Contains(escaped, `\"`) {
			t.Error("escaped mode should contain escaped quotes")
		}
	}
}
