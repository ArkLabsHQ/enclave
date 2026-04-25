package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/transport"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"golang.org/x/sync/errgroup"
)

// Layer-2 virtual network constants. Must match the values the in-enclave
// nitriding daemon and start.sh agree on (gateway IP is used as the nameserver).
const (
	gvproxyGatewayIP  = "192.168.127.1"
	gvproxyGatewayMAC = "5a:94:ef:e4:0c:dd"
	gvproxyVMIP       = "192.168.127.2"
	gvproxyVMMAC      = "5a:94:ef:e4:0c:ee"
	gvproxyHostNAT    = "192.168.127.254"
	gvproxySubnet     = "192.168.127.0/24"
	gvproxyMTU        = 1500
)

// runGvproxy starts the in-process gvproxy virtual network. Listens on
// AF_VSOCK port 1024 (the enclave dials CID_HOST:1024 to establish the L2
// tunnel). Exits when ctx is cancelled.
//
// ready is closed once the vsock listener is bound so the watchdog can
// safely issue run-enclave.
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
// Forwards map that binds the host port and routes to the VM.
//
// Each token is either:
//   - "PORT"         — same-port mapping (host:PORT → VM:PORT)
//   - "HOST:VM"      — asymmetric mapping (host:HOST → VM:VM)
//
// Example: "8443:443 7073 9090" → host:8443→VM:443, host:7073→VM:7073,
// host:9090→VM:9090. The asymmetric form lets the integration test run
// nitriding TLS on unprivileged port 8443 while the enclave keeps the
// conventional :443 internally.
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
