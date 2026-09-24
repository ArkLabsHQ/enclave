package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ArkLabsHQ/enclave/runtime/nitriding"
	"github.com/ArkLabsHQ/enclave/runtime/viproxy"
	"github.com/mdlayher/vsock"
)

func StartNetorking(ctx context.Context, cfg Config) error {
	// EIF rootfs doesn't symlink /etc/resolv.conf to gvproxy's DNS; write it directly.
	if err := os.WriteFile(
		"/etc/resolv.conf",
		[]byte("nameserver 192.168.127.1\n"),
		0o644,
	); err != nil {
		slog.Debug("write /etc/resolv.conf", "error", err)
	}

	// Start IMDS proxy before AWS clients load credentials.
	if err := startViproxy(cfg); err != nil {
		return fmt.Errorf("failed to start viproxy: %w", err)
	}

	if nitriding.InEnclave() {
		if err := nitriding.SetFdLimit(0, 0); err != nil {
			slog.Warn("set fd limit", "error", err)
		}
		if err := nitriding.ConfigureLoIface(); err != nil {
			return fmt.Errorf("failed to start enclave HTTP server %w", err)
		}
	}

	go nitriding.RunNetworking(ctx, cfg.HostProxyPort)

	return nil
}

// startViproxy launches the in-process IMDS forwarder
func startViproxy(cfg Config) error {
	in, err := parseViproxyAddr(cfg.ViproxyInAddr)
	if err != nil {
		return fmt.Errorf("parse IN addr: %w", err)
	}
	out, err := parseViproxyAddr(cfg.ViproxyOutAddr)
	if err != nil {
		return fmt.Errorf("parse OUT addr: %w", err)
	}

	px := viproxy.NewVIProxy([]*viproxy.Tuple{{InAddr: in, OutAddr: out}})
	if err := px.Start(); err != nil {
		return fmt.Errorf("viproxy start: %w", err)
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
