package nitriding

import (
	"errors"
	"log"
	"os"
)

var (
	elog = log.New(os.Stderr, "nitriding: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
	// inEnclave is true when /dev/nsm is present.
	inEnclave = false
)

// InEnclave reports whether the process is running inside a Nitro Enclave.
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
