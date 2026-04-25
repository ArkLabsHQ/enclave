package runtime

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/viproxy"
	"github.com/mdlayher/vsock"
)

// Viproxy defaults match the former /app/proxy invocation from start.sh:
//
//	IN_ADDRS=127.0.0.1:80 OUT_ADDRS=3:8002 /app/proxy
//
// Inside the enclave, local traffic to 127.0.0.1:80 (the AWS SDK's IMDS
// endpoint) is forwarded over AF_VSOCK to the EC2 host (CID 3) on port 8002,
// where the host supervisor's IMDS forwarder reaches the real 169.254.169.254.
const (
	viproxyDefaultIn  = "127.0.0.1:80"
	viproxyDefaultOut = "3:8002"
	imdsEndpointEnv   = "AWS_EC2_METADATA_SERVICE_ENDPOINT"
)

// StartViproxy launches the in-process IMDS forwarder unless disabled via
// ENCLAVE_VIPROXY_ENABLED=false. It returns once the listener is bound.
//
// Also sets AWS_EC2_METADATA_SERVICE_ENDPOINT so the AWS SDK targets the
// local forwarder instead of the real (unreachable from inside an enclave)
// 169.254.169.254.
func StartViproxy() error {
	if strings.EqualFold(envDefault("ENCLAVE_VIPROXY_ENABLED", "true"), "false") {
		return nil
	}

	in, err := parseViproxyAddr(envDefault("ENCLAVE_VIPROXY_IN_ADDRS", viproxyDefaultIn))
	if err != nil {
		return fmt.Errorf("parse IN addr: %w", err)
	}
	out, err := parseViproxyAddr(envDefault("ENCLAVE_VIPROXY_OUT_ADDRS", viproxyDefaultOut))
	if err != nil {
		return fmt.Errorf("parse OUT addr: %w", err)
	}

	px := viproxy.NewVIProxy([]*viproxy.Tuple{{InAddr: in, OutAddr: out}})
	if err := px.Start(); err != nil {
		return fmt.Errorf("viproxy start: %w", err)
	}

	if os.Getenv(imdsEndpointEnv) == "" {
		_ = os.Setenv(imdsEndpointEnv, "http://127.0.0.1:80")
	}
	return nil
}

// parseViproxyAddr accepts either a TCP address ("host:port") or a VSOCK
// address in CID:PORT form (e.g., "3:8002"). Matches the upstream viproxy
// CLI's parsing so the existing ENCLAVE_VIPROXY_{IN,OUT}_ADDRS env vars keep
// working verbatim.
func parseViproxyAddr(raw string) (net.Addr, error) {
	if addr, err := net.ResolveTCPAddr("tcp", raw); err == nil {
		return addr, nil
	}
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid addr %q (expected host:port or cid:port)", raw)
	}
	cid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid CID %q: %w", parts[0], err)
	}
	port, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", parts[1], err)
	}
	return &vsock.Addr{ContextID: uint32(cid), Port: uint32(port)}, nil
}
