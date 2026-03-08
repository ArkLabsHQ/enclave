package introspector_enclave

import (
	_ "embed"
	"encoding/json"
)

// These variables are set at build time via ldflags:
//
//	go build -ldflags "-X github.com/ArkLabsHQ/introspector-enclave.sdkRev=..."
//
// Release builds (via Makefile / CI) populate these from sdk-hashes.json.
// When ldflags are not set (e.g. go install ...@latest), the embedded
// sdk-hashes.json provides the defaults.
var (
	sdkRev        string // SDK git commit SHA or tag
	sdkHash       string // Nix source hash (SRI format, e.g. sha256-...)
	sdkVendorHash string // Go vendor hash (SRI format, e.g. sha256-...)
)

//go:embed sdk-hashes.json
var sdkHashesJSON []byte

func init() {
	// Only apply embedded defaults when ldflags haven't set the values.
	if sdkRev != "" {
		return
	}
	var h struct {
		Rev        string `json:"rev"`
		Hash       string `json:"hash"`
		VendorHash string `json:"vendor_hash"`
	}
	if err := json.Unmarshal(sdkHashesJSON, &h); err != nil {
		return
	}
	sdkRev = h.Rev
	sdkHash = h.Hash
	sdkVendorHash = h.VendorHash
}
