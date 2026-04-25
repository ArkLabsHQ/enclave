package runtime

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ArkLabsHQ/introspector-enclave/runtime/nitriding"
)

// BuildNitridingConfig constructs a nitriding.Config from the same ENCLAVE_*
// env vars that the former stand-alone nitriding daemon consumed via CLI flags.
// Returns an error if required fields are missing or a port is out of range.
//
// The caller passes this config to nitriding.NewEnclave.
func BuildNitridingConfig() (*nitriding.Config, error) {
	extPort, err := envUint16("ENCLAVE_NITRIDING_EXT_PORT", 443)
	if err != nil {
		return nil, err
	}
	intPort, err := envUint16("ENCLAVE_NITRIDING_INT_PORT", 8080)
	if err != nil {
		return nil, err
	}
	promPort, err := envUint16("ENCLAVE_NITRIDING_PROM_PORT", 9090)
	if err != nil {
		return nil, err
	}
	hostProxyPort, err := envUint32("ENCLAVE_NITRIDING_HOST_PROXY_PORT", 1024)
	if err != nil {
		return nil, err
	}

	proxyPort := envDefault("ENCLAVE_PROXY_PORT", "7073")
	appWebSrv, err := url.Parse("http://127.0.0.1:" + proxyPort)
	if err != nil {
		return nil, fmt.Errorf("parse app web srv url: %w", err)
	}

	cfg := &nitriding.Config{
		FQDN:                envDefault("ENCLAVE_NITRIDING_FQDN", "localhost"),
		ExtPort:             extPort,
		IntPort:             intPort,
		HostProxyPort:       hostProxyPort,
		PrometheusPort:      promPort,
		PrometheusNamespace: envDefault("ENCLAVE_NITRIDING_PROM_NAMESPACE", "enclave"),
		AppWebSrv:           appWebSrv,
		WaitForApp:          false, // runtime binds IntPort itself; the /ready gate is irrelevant when nitriding runs in-process
		Debug:               strings.EqualFold(os.Getenv("ENCLAVE_NITRIDING_DEBUG"), "true"),
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
