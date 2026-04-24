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
	elog      = log.New(os.Stderr, "nitriding: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	inEnclave = false
)

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
