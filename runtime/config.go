package runtime

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config holds runtime HTTP/network settings.
type Config struct {
	FQDN             string   // Hostname the TLS cert is issued for.
	ExtPort          uint16   // External TLS listener.
	IntPort          uint16   // Internal loopback HTTP listener.
	HostProxyPort    uint32   // Vsock port the host-side gvproxy listens on.
	UseACME          bool     // Use ACME instead of self-signed TLS.
	ACMEDirectory    string   // ACME dir override: "letsencrypt-staging" or https:// URL.
	ACMEEmail        string   // Optional ACME account contact email.
	ACMECA           string   // PEM CA bundle for private/test ACME HTTPS.
	AppWebSrv        *url.URL // Loopback URL the catch-all revProxy forwards to.
	UpstreamProtocol string   // revProxy-to-app HTTP version: auto (match inbound), h2c, or h1.
}

// LoadConfig builds Config from ENCLAVE_* env vars.
func LoadConfig() (*Config, error) {
	extPort, err := envUint16("ENCLAVE_NITRIDING_EXT_PORT", 443)
	if err != nil {
		return nil, err
	}
	intPort, err := envUint16("ENCLAVE_NITRIDING_INT_PORT", 8080)
	if err != nil {
		return nil, err
	}
	hostProxyPort, err := envUint32("ENCLAVE_NITRIDING_HOST_PROXY_PORT", 1024)
	if err != nil {
		return nil, err
	}

	// Point the reverse proxy directly at the user app.
	appPort := envDefault("ENCLAVE_APP_PORT", "7074")
	appWebSrv, err := url.Parse("http://127.0.0.1:" + appPort)
	if err != nil {
		return nil, fmt.Errorf("parse app web srv url: %w", err)
	}

	cfg := &Config{
		FQDN:             envDefault("ENCLAVE_NITRIDING_FQDN", "localhost"),
		ExtPort:          extPort,
		IntPort:          intPort,
		HostProxyPort:    hostProxyPort,
		AppWebSrv:        appWebSrv,
		UpstreamProtocol: strings.ToLower(envDefault("ENCLAVE_NITRIDING_UPSTREAM", "auto")),
	}
	return cfg, nil
}

// Validate checks required listener settings.
func (c *Config) Validate() error {
	if c.ExtPort == 0 || c.IntPort == 0 || c.HostProxyPort == 0 {
		return fmt.Errorf("config is missing port")
	}
	if c.FQDN == "" {
		return fmt.Errorf("config is missing FQDN")
	}
	return validateEnvironment()
}

func (c *Config) String() string {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "failed to marshal config"
	}
	return string(b)
}

func envDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envUint16(key string, fallback uint16) (uint16, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return uint16(n), nil
}

func envUint32(key string, fallback uint32) (uint32, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return uint32(n), nil
}
