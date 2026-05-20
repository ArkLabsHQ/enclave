package cli

import "testing"

func TestReplaceRuntimeBlockValue(t *testing.T) {
	// A realistic enclave.yaml: a runtime: block plus an app: block whose
	// nix_rev / nix_hash / nix_vendor_hash keys are deliberate collision bait
	// for a naive substring replace.
	const sample = `name: "my-app"

runtime:
  rev: "v0.0.62"
  hash: "sha256-OLD="
  vendor_hash: "sha256-OLDV="

app:
  language: "go"
  nix_rev: "abc123"
  nix_hash: "sha256-NIX="
  nix_vendor_hash: "sha256-NIXV="
`

	tests := []struct {
		name     string
		content  string
		key      string
		newValue string
		want     string
		wantErr  bool
	}{
		{
			name:     "rev does not touch nix_rev",
			content:  sample,
			key:      "rev",
			newValue: "v0.0.99",
			want: `name: "my-app"

runtime:
  rev: "v0.0.99"
  hash: "sha256-OLD="
  vendor_hash: "sha256-OLDV="

app:
  language: "go"
  nix_rev: "abc123"
  nix_hash: "sha256-NIX="
  nix_vendor_hash: "sha256-NIXV="
`,
		},
		{
			name:     "hash does not touch vendor_hash or nix_hash",
			content:  sample,
			key:      "hash",
			newValue: "sha256-NEW=",
			want: `name: "my-app"

runtime:
  rev: "v0.0.62"
  hash: "sha256-NEW="
  vendor_hash: "sha256-OLDV="

app:
  language: "go"
  nix_rev: "abc123"
  nix_hash: "sha256-NIX="
  nix_vendor_hash: "sha256-NIXV="
`,
		},
		{
			name:     "vendor_hash does not touch nix_vendor_hash",
			content:  sample,
			key:      "vendor_hash",
			newValue: "sha256-NEWV=",
			want: `name: "my-app"

runtime:
  rev: "v0.0.62"
  hash: "sha256-OLD="
  vendor_hash: "sha256-NEWV="

app:
  language: "go"
  nix_rev: "abc123"
  nix_hash: "sha256-NIX="
  nix_vendor_hash: "sha256-NIXV="
`,
		},
		{
			name:     "preserves inline comment and missing trailing newline",
			content:  "runtime:\n  rev: \"v0.0.62\"   # pinned runtime tag",
			key:      "rev",
			newValue: "v0.0.99",
			want:     "runtime:\n  rev: \"v0.0.99\"   # pinned runtime tag",
		},
		{
			name:     "replaces empty value",
			content:  "runtime:\n  rev: \"\"\n  hash: \"\"\n  vendor_hash: \"\"\n",
			key:      "rev",
			newValue: "v0.0.99",
			want:     "runtime:\n  rev: \"v0.0.99\"\n  hash: \"\"\n  vendor_hash: \"\"\n",
		},
		{
			name:     "preserves multi-space after colon",
			content:  "runtime:\n  rev:   \"v0.0.62\"\n",
			key:      "rev",
			newValue: "v0.0.99",
			want:     "runtime:\n  rev:   \"v0.0.99\"\n",
		},
		{
			name:     "bare key with no spacing yields valid YAML",
			content:  "runtime:\n  rev:\n",
			key:      "rev",
			newValue: "v0.0.99",
			want:     "runtime:\n  rev: \"v0.0.99\"\n",
		},
		{
			name:     "runtime key with trailing comment is detected",
			content:  "runtime:  # supervisor coordinates\n  rev: \"v0.0.62\"\n",
			key:      "rev",
			newValue: "v0.0.99",
			want:     "runtime:  # supervisor coordinates\n  rev: \"v0.0.99\"\n",
		},
		{
			name:    "no runtime block is an error",
			content: "name: \"x\"\napp:\n  nix_rev: \"a\"\n",
			key:     "rev",
			wantErr: true,
		},
		{
			name:    "key outside the runtime block is not matched",
			content: "runtime:\n  rev: \"v0.0.62\"\napp:\n  hash: \"do-not-touch\"\n",
			key:     "hash",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := replaceRuntimeBlockValue(tt.content, tt.key, tt.newValue)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (output %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got:\n%q\nwant:\n%q", got, tt.want)
			}
		})
	}
}

func TestYamlKeyOf(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`rev: "v1"`, "rev"},
		{`nix_rev: "v1"`, "nix_rev"},
		{`hash: "x"`, "hash"},
		{`vendor_hash: "x"`, "vendor_hash"},
		{`nix_vendor_hash: "x"`, "nix_vendor_hash"},
		{"runtime:", "runtime"},
		{"runtime:  # comment", "runtime"},
		{"no-colon-here", ""},
	}
	for _, tt := range tests {
		if got := yamlKeyOf(tt.in); got != tt.want {
			t.Errorf("yamlKeyOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
