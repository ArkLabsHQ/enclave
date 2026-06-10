package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestVendorCommandFor_Rust(t *testing.T) {
	name, args, err := vendorCommandFor("rust")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "cargo" || !equalStrings(args, []string{"vendor"}) {
		t.Errorf("rust → got %q %v, want cargo [vendor]", name, args)
	}
}

func TestVendorCommandFor_Go(t *testing.T) {
	name, args, err := vendorCommandFor("go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name != "go" || !equalStrings(args, []string{"mod", "vendor"}) {
		t.Errorf("go → got %q %v, want go [mod vendor]", name, args)
	}
}

func TestVendorCommandFor_UnsupportedLanguages(t *testing.T) {
	tests := []struct {
		lang            string
		wantErrContains string
	}{
		{"nodejs", "vendor mode is not supported for language=nodejs"},
		{"dotnet", "vendor mode is not needed for language=dotnet"},
		{"python", `unknown language "python"`},
		{"", `unknown language ""`},
		{"RUST", `unknown language "RUST"`},
	}
	for _, tt := range tests {
		t.Run(tt.lang, func(t *testing.T) {
			_, _, err := vendorCommandFor(tt.lang)
			requireErrContains(t, err, tt.wantErrContains)
		})
	}
}

func TestResolveVendorCwd_NoSubdir(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveVendorCwd(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(dir)
	if got != abs {
		t.Errorf("got %q, want %q", got, abs)
	}
}

func TestResolveVendorCwd_WithSubdir(t *testing.T) {
	dir := t.TempDir()
	got, err := resolveVendorCwd(dir, "cosigner-runtime")
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(dir)
	want := filepath.Join(abs, "cosigner-runtime")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFrameworkFlakeRust_VendorConditional(t *testing.T) {
	rust := applyNixpkgsRef(frameworkFlakeNixRust, "")
	wants := []string{
		`if (appCfg.vendor or false)`,
		`then { cargoVendorDir = "vendor"; }`,
		`else { cargoHash =`,
		`runCommand "vendor-hash-check-noop"`,
	}
	for _, w := range wants {
		if !strings.Contains(rust, w) {
			t.Errorf("Rust flake template missing fragment %q", w)
		}
	}
}

func TestFrameworkFlakeGo_VendorConditional(t *testing.T) {
	gop := applyNixpkgsRef(frameworkFlakeNix, "")
	wants := []string{
		`vendorHash = if (appCfg.vendor or false) then null`,
		`proxyVendor = !(appCfg.vendor or false);`,
		`runCommand "vendor-hash-check-noop"`,
	}
	for _, w := range wants {
		if !strings.Contains(gop, w) {
			t.Errorf("Go flake template missing fragment %q", w)
		}
	}
}

func TestFrameworkFlakeNodejs_NoVendorConditional(t *testing.T) {
	node := applyNixpkgsRef(frameworkFlakeNixNodejs, "")
	// Node should NOT have the vendor conditional — vendor mode is rejected
	// for nodejs at config-load.
	if strings.Contains(node, `if (appCfg.vendor or false)`) {
		t.Errorf("Node flake template should not have vendor conditional (vendor mode is rejected for nodejs)")
	}
}
