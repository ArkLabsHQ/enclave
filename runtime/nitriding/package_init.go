package nitriding

// Package-level globals and init() extracted from upstream main.go, which we
// don't vendor (we own the entrypoint from runtime/cmd/runtime/main.go). These
// must stay in the vendored package because attestation.go, enclave.go,
// handlers.go, proxy.go, system_linux.go, and metrics.go all reference them.

import (
	"errors"
	"log"
	"os"
)

var (
	elog = log.New(os.Stderr, "nitriding: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	// Elog is the exported logger used by code in the runtime package after the
	// Enclave-struct merge. Same target as the legacy elog.
	Elog = elog
	// inEnclave is true when /dev/nsm is present — i.e. we're really inside
	// a Nitro Enclave rather than running locally for tests.
	inEnclave = false
)

// InEnclave reports whether the process is running inside a Nitro Enclave.
// Exported so callers in the runtime package can branch on the environment.
func InEnclave() bool { return inEnclave }

func init() {
	if _, err := os.Stat("/dev/nsm"); err == nil {
		inEnclave = true
	} else if errors.Is(err, os.ErrNotExist) {
		inEnclave = false
	} else {
		inEnclave = false
	}
	maybeSeedEntropy()
}
