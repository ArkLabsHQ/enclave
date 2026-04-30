package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/mdlayher/vsock"
	"golang.org/x/sync/errgroup"
)

// Layer-2 virtual network constants. Must match the values the in-enclave
// nitriding daemon and start.sh agree on (gateway IP is also the resolver).
const (
	gvproxyGatewayIP  = "192.168.127.1"
	gvproxyGatewayMAC = "5a:94:ef:e4:0c:dd"
	gvproxyVMIP       = "192.168.127.2"
	gvproxyVMMAC      = "5a:94:ef:e4:0c:ee"
	gvproxyHostNAT    = "192.168.127.254"
	gvproxySubnet     = "192.168.127.0/24"
	gvproxyMTU        = 1500
)

// Networking runs the two host-side bridges the enclave depends on: the
// gvproxy L2 vsock network and the IMDS proxy. Ready closes once gvproxy
// has bound vsock:1024 — the lifecycle subsystem waits on it before
// booting the enclave (nitriding dials this immediately on start).
type Networking struct {
	ready chan struct{}
}

func NewNetworking() *Networking {
	return &Networking{ready: make(chan struct{})}
}

func (n *Networking) Ready() <-chan struct{} { return n.ready }

func (n *Networking) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return runGvproxy(gctx, n.ready) })
	g.Go(func() error { return runIMDSProxy(gctx) })
	return g.Wait()
}

// runGvproxy serves the L2 vsock network on port 1024. Closes ready once
// the listener is bound. Exits on ctx cancellation.
func runGvproxy(ctx context.Context, ready chan<- struct{}) error {
	forwards, err := parseForwardPorts(os.Getenv("GVPROXY_FORWARD_PORTS"))
	if err != nil {
		return fmt.Errorf("parse GVPROXY_FORWARD_PORTS: %w", err)
	}

	cfg := &types.Configuration{
		MTU:               gvproxyMTU,
		Subnet:            gvproxySubnet,
		GatewayIP:         gvproxyGatewayIP,
		GatewayMacAddress: gvproxyGatewayMAC,
		GatewayVirtualIPs: []string{gvproxyHostNAT},
		NAT:               map[string]string{gvproxyHostNAT: "127.0.0.1"},
		DHCPStaticLeases:  map[string]string{gvproxyVMIP: gvproxyVMMAC},
		Forwards:          forwards,
		Protocol:          types.HyperKitProtocol,
		DNS: []types.Zone{
			{
				Name: "containers.internal.",
				Records: []types.Record{
					{Name: "gateway", IP: net.ParseIP(gvproxyGatewayIP)},
					{Name: "host", IP: net.ParseIP(gvproxyHostNAT)},
				},
			},
		},
	}

	vn, err := virtualnetwork.New(cfg)
	if err != nil {
		return fmt.Errorf("virtualnetwork.New: %w", err)
	}

	endpoint := envOrDefault("GVPROXY_LISTEN", transport.DefaultURL)
	ln, err := transport.Listen(endpoint)
	if err != nil {
		return fmt.Errorf("gvproxy listen %s: %w", endpoint, err)
	}
	slog.Info("gvproxy listening", "endpoint", endpoint, "forwards", forwards)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-gctx.Done()
		return ln.Close()
	})

	g.Go(func() error {
		srv := &http.Server{
			Handler:      vn.Mux(),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("gvproxy serve: %w", err)
		}
		return nil
	})

	close(ready)

	err = g.Wait()
	if err != nil && gctx.Err() != nil {
		return nil
	}
	return err
}

// parseForwardPorts turns a whitespace-separated spec into a gvproxy
// Forwards map. Each token is "PORT" (same-port host:PORT → VM:PORT) or
// "HOST:VM" (asymmetric). The asymmetric form lets tests bind nitriding
// TLS on unprivileged 8443 while the enclave keeps :443 internally.
func parseForwardPorts(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, tok := range strings.Fields(spec) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		hostPort, vmPort, ok := strings.Cut(tok, ":")
		if !ok {
			vmPort = hostPort
		}
		if _, err := net.LookupPort("tcp", hostPort); err != nil {
			return nil, fmt.Errorf("invalid host port %q: %w", hostPort, err)
		}
		if _, err := net.LookupPort("tcp", vmPort); err != nil {
			return nil, fmt.Errorf("invalid VM port %q: %w", vmPort, err)
		}
		out[":"+hostPort] = gvproxyVMIP + ":" + vmPort
	}
	return out, nil
}

// IMDS proxy: replaces the upstream vsock-proxy from aws-nitro-enclaves-cli.
// The enclave's viproxy dials CID_HOST:8002; we pipe bytes to
// 169.254.169.254:80.
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
