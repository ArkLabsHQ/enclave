package runtime

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	prodRetention         = 10 * 365 * 24 * time.Hour
	prodMigrationCooldown = 24 * time.Hour

	devGenesisRetention  = 5 * time.Minute
	devIntentRetention   = time.Minute
	devMigrationCooldown = 2 * time.Second
)

const (
	// extPort is the public TLS listener. Fixed: the host's routing, the README
	// and every client URL assume 443.
	extPort = 443

	// intPort is the loopback API listener, handed to the application as
	// ENCLAVE_PROXY_PORT so it does not have to assume the value.
	intPort = 8080

	// hostProxyPort is the vsock port gvproxy listens on. Fixed because the host
	// side hardcodes it too (`gvproxy --listen vsock://:1024`); changing one side
	// alone silently breaks all networking.
	hostProxyPort = 1024
)

// Config holds runtime HTTP/network settings, the enclave's identity, and the
// security settings the measured image settles rather than an operator.
type Config struct {
	// Identity. EIF-baked and part of PCR0, so it cannot change once loaded —
	// which is the point: every SSM path is derived from these, and a later
	// os.Setenv (the SSM overlay, or a static secret's env var) must not be able
	// to move the namespace out from under a running enclave.
	Deployment string
	AppName    string
	Dev        bool

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

	KMSLocked             bool
	InsecureVerifySkipped bool
	VerifyClockSource     bool
	GenesisRetention      time.Duration
	IntentRetention       time.Duration
	MigrationCooldown     time.Duration
}

// LoadConfig builds Config from ENCLAVE_* env vars.
func LoadConfig() (*Config, error) {
	// Point the reverse proxy directly at the user app.
	appPort := getAppPort()
	appWebSrv, err := url.Parse("http://127.0.0.1:" + appPort)
	if err != nil {
		return nil, fmt.Errorf("parse app web srv url: %w", err)
	}

	cfg := &Config{
		Deployment: getDeployment(),
		AppName:    getAppName(),

		FQDN:             getFQDN(),
		ExtPort:          extPort,
		IntPort:          intPort,
		HostProxyPort:    hostProxyPort,
		AppWebSrv:        appWebSrv,
		UpstreamProtocol: getUpstreamProtocol(),
	}
	cfg.setSecurityConfig(IsDev())
	return cfg, nil
}

// Validate rejects an unusable config before any state is touched.
func (c *Config) Validate() error {
	if c.ExtPort == 0 || c.IntPort == 0 || c.HostProxyPort == 0 {
		return fmt.Errorf("config is missing port")
	}
	if c.FQDN == "" {
		return fmt.Errorf("config is missing FQDN")
	}
	if c.Deployment == "" {
		return fmt.Errorf("ENCLAVE_DEPLOYMENT must be set: it namespaces all SSM state")
	}
	if c.AppName == "" {
		return fmt.Errorf("ENCLAVE_APP_NAME must be set: it namespaces all SSM state")
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

func (c *Config) lockSegment() string {
	if c.KMSLocked {
		return "locked"
	}
	return "unlocked"
}

func (c *Config) setSecurityConfig(dev bool) {
	c.Dev = dev
	c.KMSLocked = !dev
	c.VerifyClockSource = !dev

	if dev {
		c.GenesisRetention = devGenesisRetention
		c.IntentRetention = devIntentRetention
		c.MigrationCooldown = devMigrationCooldown
		return
	}
	c.GenesisRetention = prodRetention
	c.IntentRetention = prodRetention
	c.MigrationCooldown = prodMigrationCooldown
}

func (c *Config) certBucketParam() string {
	return fmt.Sprintf("/%s/%s/CertBucketName", c.Deployment, c.AppName)
}

func (c *Config) leaseBucketParam() string {
	return fmt.Sprintf("/%s/%s/LeaseBucketName", c.Deployment, c.AppName)
}

func (c *Config) route53ZoneIDParam() string {
	return fmt.Sprintf("/%s/%s/Route53ZoneID", c.Deployment, c.AppName)
}

func (c *Config) kmsKeyIDParam(pcr0 string) string {
	return fmt.Sprintf(
		"/%s/%s/%s/KMSKeyID/%s",
		c.Deployment,
		c.AppName,
		c.lockSegment(),
		strings.ToLower(pcr0),
	)
}

// secretCiphertextParam: SSM path for a secret's KMS ciphertext, lock-scoped and
// scoped by the KMS key ID. Flipping the KMSKeyID param is the atomic migration commit.
func (c *Config) secretCiphertextParam(secretName, keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/%s/%s/Ciphertext/%s",
		c.Deployment,
		c.AppName,
		c.lockSegment(),
		secretName,
		keyID,
	)
}

// storageDEKCiphertextParam: SSM path for the storage DEK's KMS ciphertext, lock-scoped and key-scoped.
func (c *Config) storageDEKCiphertextParam(keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/%s/StorageDEK/Ciphertext/%s",
		c.Deployment,
		c.AppName,
		c.lockSegment(),
		keyID,
	)
}

// tlsKeyCiphertextParam returns the encrypted TLS key path.
func (c *Config) tlsKeyCiphertextParam(keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/%s/TLSKey/Ciphertext/%s",
		c.Deployment, c.AppName, c.lockSegment(), keyID,
	)
}

// stateOriginReceiptParam: SSM path for the receipt an enclave writes over its
// own state at genesis (and after adopting a migration). Scoped by key ID and PCR0.
func (c *Config) stateOriginReceiptParam(keyID, pcr0 string) string {
	return fmt.Sprintf(
		"/%s/%s/StateOriginReceipt/%s/%s",
		c.Deployment,
		c.AppName,
		keyID,
		strings.ToLower(pcr0),
	)
}

// migrationStateOriginReceiptParam: SSM path for the receipt a predecessor
// writes over a successor's state during a migration handoff. Scoped by the
// successor key ID.
func (c *Config) migrationStateOriginReceiptParam(keyID string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationStateOriginReceipt/%s",
		c.Deployment,
		c.AppName,
		keyID,
	)
}

// migrationPreviousPCR0Param: SSM path for the predecessor enclave's PCR0,
// scoped by the successor PCR0 that reads it.
func (c *Config) migrationPreviousPCR0Param(pcr0 string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationPreviousPCR0/%s",
		c.Deployment,
		c.AppName,
		strings.ToLower(pcr0),
	)
}

// migrationPreviousKMSKeyIDParam returns the predecessor key path for a generation.
func (c *Config) migrationPreviousKMSKeyIDParam(pcr0 string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationPreviousKMSKeyID/%s",
		c.Deployment, c.AppName, strings.ToLower(pcr0),
	)
}

// migrationPreviousPCR0AttestationParam: SSM path for the predecessor enclave's
// attestation document, scoped by the successor PCR0 that reads it.
func (c *Config) migrationPreviousPCR0AttestationParam(pcr0 string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationPreviousPCR0Attestation/%s",
		c.Deployment,
		c.AppName,
		strings.ToLower(pcr0),
	)
}

func (c *Config) envVarOverridePath(name string) string {
	return fmt.Sprintf("/%s/%s/env/%s", c.Deployment, c.AppName, name)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
