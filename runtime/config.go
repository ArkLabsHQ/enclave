package runtime

import (
	"encoding/json"
	"net/url"
)

// =============================================================================
// Public types
// =============================================================================

// Config is the runtime's HTTP and networking configuration, populated from
// ENCLAVE_* environment variables by BuildNitridingConfig.
type Config struct {
	FQDN               string   // Hostname the TLS cert is issued for.
	ExtPort            uint16   // External TLS listener.
	UseVsockForExtPort bool     // Listen on AF_VSOCK instead of AF_INET.
	DisableKeepAlives  bool     // Disable HTTP keep-alives on the TLS server.
	IntPort            uint16   // Internal loopback HTTP listener.
	HostProxyPort      uint32   // Vsock port the host-side gvproxy listens on.
	UseProfiling       bool     // Mount net/http/pprof at /enclave/debug.
	UseACME            bool     // Use ACME (Let's Encrypt) instead of a self-signed cert.
	ACMEDirectory      string   // ACME directory: keyword (letsencrypt | letsencrypt-staging | self-signed) or a literal https:// directory URL.
	ACMEEmail          string   // Optional ACME account contact email.
	ACMECA             string   // Optional PEM CA bundle trusted for the ACME directory's HTTPS API (private/test ACME servers).
	Debug              bool     // Verbose chi request logging.
	FdCur, FdMax       uint64   // File-descriptor soft/hard limits.
	AppURL             *url.URL // Public source URL of the user app (informational).
	AppWebSrv          *url.URL // Loopback URL the catch-all revProxy forwards to.
	WaitForApp         bool     // Block TLS listener until the app POSTs /enclave/ready.
	MockCertFp         string   // Test-only override for the TLS cert fingerprint.
}

// Validate returns an error if any required field is unset.
func (c *Config) Validate() error {
	if c.ExtPort == 0 || c.IntPort == 0 || c.HostProxyPort == 0 {
		return errCfgMissingPort
	}
	if c.FQDN == "" {
		return errCfgMissingFQDN
	}
	return nil
}

func (c *Config) String() string {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "failed to marshal config"
	}
	return string(b)
}
