package cli

import (
	_ "embed"
	"encoding/json"
)

// These variables are set at build time via ldflags:
//
//	go build -ldflags "-X github.com/ArkLabsHQ/introspector-enclave/cli.runtimeRev=..."
//
// Release builds (via Makefile / CI) populate these from runtime-hashes.json.
// When ldflags are not set (e.g. go install ...@latest), the embedded
// runtime-hashes.json provides the defaults.
var (
	runtimeRev        string // SDK git commit SHA or tag
	runtimeHash       string // Nix source hash (SRI format, e.g. sha256-...)
	runtimeVendorHash string // Go vendor hash (SRI format, e.g. sha256-...)
)

//go:embed runtime-hashes.json
var runtimeHashesJSON []byte

func init() {
	// Only apply embedded defaults when ldflags haven't set the values.
	if runtimeRev != "" {
		return
	}
	var h struct {
		Rev        string `json:"rev"`
		Hash       string `json:"hash"`
		VendorHash string `json:"vendor_hash"`
	}
	if err := json.Unmarshal(runtimeHashesJSON, &h); err != nil {
		return
	}
	runtimeRev = h.Rev
	runtimeHash = h.Hash
	runtimeVendorHash = h.VendorHash
}
