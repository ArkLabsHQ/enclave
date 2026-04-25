package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/mdlayher/vsock"
)

// IMDS proxy forwards AF_VSOCK connections from the enclave to the host's
// IMDSv2 endpoint. Replaces the upstream `vsock-proxy` binary from
// aws-nitro-enclaves-cli. The enclave's viproxy dials CID_HOST:8002; this
// forwarder accepts those and pipes bytes to 169.254.169.254:80.
const (
	imdsDefaultPort   = 8002
	imdsTargetAddr    = "169.254.169.254:80"
	imdsDialTimeout   = 5 * time.Second
	imdsAcceptBackoff = 500 * time.Millisecond
)

func runIMDSProxy(ctx context.Context) error {
	port := imdsDefaultPort
	if v := envOrDefault("IMDS_PROXY_VSOCK_PORT", ""); v != "" {
		p, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid IMDS_PROXY_VSOCK_PORT %q: %w", v, err)
		}
		port = int(p)
	}

	target := envOrDefault("IMDS_PROXY_TARGET", imdsTargetAddr)

	ln, err := vsock.Listen(uint32(port), nil)
	if err != nil {
		return fmt.Errorf("vsock.Listen(%d): %w", port, err)
	}
	slog.Info("imds proxy listening", "vsock_port", port, "target", target)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("imds accept failed", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(imdsAcceptBackoff):
			}
			continue
		}
		go handleIMDSConn(ctx, conn, target)
	}
}

func handleIMDSConn(ctx context.Context, src net.Conn, target string) {
	defer func() { _ = src.Close() }()

	dctx, cancel := context.WithTimeout(ctx, imdsDialTimeout)
	defer cancel()
	d := net.Dialer{}
	dst, err := d.DialContext(dctx, "tcp", target)
	if err != nil {
		slog.Error("imds upstream dial failed", "target", target, "error", err)
		return
	}
	defer func() { _ = dst.Close() }()

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(dst, src); errCh <- err }()
	go func() { _, err := io.Copy(src, dst); errCh <- err }()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) && err != io.EOF {
			slog.Debug("imds copy ended", "error", err)
		}
	}
}
