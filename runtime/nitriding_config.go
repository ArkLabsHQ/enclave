package runtime

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// BuildNitridingConfig constructs a *Config from the same ENCLAVE_* env vars
// the former stand-alone nitriding daemon consumed via CLI flags. The caller
// passes this config to runtime.New() — there is no longer a separate
// nitriding.Enclave constructor.
func BuildNitridingConfig() (*Config, error) {
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

	// Point directly at the user app — there is no longer an intermediate
	// runtime proxy on :7073 in the external path. Runtime's management
	// routes mount on the public chi mux via PubMux(); the catch-all
	// revProxy reaches the user app in one hop.
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
		WaitForApp:       false, // runtime binds IntPort itself; the /ready gate is irrelevant when nitriding runs in-process
		Debug:            strings.EqualFold(os.Getenv("ENCLAVE_NITRIDING_DEBUG"), "true"),
	}
	return cfg, nil
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
