package introspector_enclave

import (
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

