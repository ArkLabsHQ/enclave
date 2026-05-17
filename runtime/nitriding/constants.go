package nitriding

const (
	// parentCID is the vsock CID of the parent EC2 instance. Per AWS docs
	// it's always 3:
	// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
	parentCID = 3

	// HTTP paths the keysync initiator dials on a remote enclave.
	pathNonce = "/enclave/nonce"
	pathSync  = "/enclave/sync"
)
