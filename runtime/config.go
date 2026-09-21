package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	prodRetention          = 10 * 365 * 24 * time.Hour
	prodIntentWriteTimeout = 10 * time.Minute
	// 5 min matches Evervault's /dev/ptp0 sync cadence:
	// https://evervault.com/blog/how-we-built-enclaves-resolving-clock-drift-in-nitro-enclaves.
	prodClockSyncInterval = 5 * time.Minute

	devGenesisRetention   = 5 * time.Minute
	devIntentRetention    = 10 * time.Minute
	devIntentWriteTimeout = 2 * time.Minute
	devClockSyncInterval  = 5 * time.Second

	defaulMigrationCooldown = 24 * time.Hour
	defaultLogShipInterval  = 10 * time.Second
	defaultLogRetentionDays = int32(30)
	logGroupRoot            = "enclave"

	logGroupNameChars = "._-/#"

	migrationPollInterval    = 5 * time.Second
	migrationChallengeRotate = time.Minute

	migrationAbortResponse = "abort"
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
	Deployment   string
	AppName      string
	AppPort      string
	PreviousPCR0 string

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
	IntentWriteTimeout    time.Duration
	MigrationCooldown     time.Duration
	ClockSyncInterval     time.Duration
	LogShipInterval       time.Duration
	LogRetentionDays      int32
	LogGroupPrefix        string
	InstanceID            string
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
		Deployment:   getDeployment(),
		AppName:      getAppName(),
		AppPort:      appPort,
		PreviousPCR0: getPreviousPCR0(),

		FQDN:                  getFQDN(),
		ExtPort:               extPort,
		IntPort:               intPort,
		HostProxyPort:         hostProxyPort,
		AppWebSrv:             appWebSrv,
		UpstreamProtocol:      getUpstreamProtocol(),
		LogShipInterval:       logShipInterval(),
		LogRetentionDays:      logRetentionDays(),
		LogGroupPrefix:        logGroupPrefix(),
		GenesisRetention:      prodRetention,
		IntentRetention:       prodRetention,
		IntentWriteTimeout:    prodIntentWriteTimeout,
		MigrationCooldown:     defaulMigrationCooldown,
		ClockSyncInterval:     prodClockSyncInterval,
		VerifyClockSource:     true,
		InsecureVerifySkipped: false,
		KMSLocked:             true,
	}

	if IsDev() {
		cfg.KMSLocked = false
		cfg.GenesisRetention = devGenesisRetention
		cfg.IntentRetention = devIntentRetention
		cfg.IntentWriteTimeout = devIntentWriteTimeout
		cfg.ClockSyncInterval = devClockSyncInterval

		// only allow overriding cfg.InsecureVerifySkipped in dev mode
		// It is false by default unless explicitly overriden
		verifySkipped, set, err := insecureVerifySkipped()
		if err != nil {
			return nil, err
		}
		if set {
			cfg.InsecureVerifySkipped = verifySkipped
		}
	}

	verify, set, err := verifyClockSource()
	if err != nil {
		return nil, err
	}
	if set {
		cfg.VerifyClockSource = verify
	}

	cooldown, set, err := migrationCooldown()
	if err != nil {
		return nil, err
	}
	if set {
		cfg.MigrationCooldown = cooldown
	}

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
	if strings.IndexFunc(c.Deployment, invalidLogGroupRune) >= 0 {
		return fmt.Errorf(
			"ENCLAVE_DEPLOYMENT %q: it names every CloudWatch log group, which allow only "+
				"letters, digits and %s",
			c.Deployment, logGroupNameChars,
		)
	}
	if c.AppName == "" {
		return fmt.Errorf("ENCLAVE_APP_NAME must be set: it namespaces all SSM state")
	}
	if c.AppPort == "" {
		return fmt.Errorf("config is missing application process settings")
	}
	if c.LogShipInterval <= 0 || c.LogRetentionDays <= 0 {
		return fmt.Errorf("config has invalid telemetry timing")
	}
	return c.validateLogGroupPrefix()
}

func (c *Config) validateLogGroupPrefix() error {
	if c.LogGroupPrefix == "" {
		return fmt.Errorf(
			"ENCLAVE_LOG_GROUP_PREFIX must not be empty: it heads every CloudWatch log group",
		)
	}
	if strings.IndexFunc(c.LogGroupPrefix, invalidLogGroupRune) >= 0 {
		return fmt.Errorf(
			"ENCLAVE_LOG_GROUP_PREFIX %q: CloudWatch log group names allow only letters, "+
				"digits and %s",
			c.LogGroupPrefix, logGroupNameChars,
		)
	}
	return nil
}

func invalidLogGroupRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	}
	return !strings.ContainsRune(logGroupNameChars, r)
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

func (c *Config) applyEnvOverride(name, value string) error {
	switch name {
	case "ENCLAVE_APP_PORT":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("invalid application port %q", value)
		}
		appWebSrv, err := url.Parse("http://127.0.0.1:" + value)
		if err != nil {
			return fmt.Errorf("parse app web srv url: %w", err)
		}
		c.AppPort = value
		c.AppWebSrv = appWebSrv
	case "ENCLAVE_FQDN":
		c.FQDN = value
	case "ENCLAVE_USE_ACME":
		c.UseACME = strings.EqualFold(value, "true")
	case "ENCLAVE_ACME_DIRECTORY":
		c.ACMEDirectory = value
	case "ENCLAVE_ACME_EMAIL":
		c.ACMEEmail = value
	case "ENCLAVE_ACME_CA":
		c.ACMECA = value
	case "ENCLAVE_LOG_GROUP_PREFIX":
		c.LogGroupPrefix = normalizeLogGroupPrefix(value)
		if err := c.validateLogGroupPrefix(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) logGroup(sig signal) string {
	return fmt.Sprintf(
		"%s/%s/%s/%s", strings.TrimSuffix(c.LogGroupPrefix, "/"), c.Deployment, logGroupRoot, sig,
	)
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

// storageDEKCiphertextParam: SSM path for the storage DEK's KMS ciphertext,
// lock-scoped and key-scoped.
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
// successor key ID and the successor PCR0, and written create-only, so a
// published handoff artifact is immutable. The key ID is minted fresh per
// finalisation attempt, so this path is private to one attempt; the atomic
// commitment point for a handoff is kmsKeyIDParam, not this receipt.
func (c *Config) migrationStateOriginReceiptParam(keyID, pcr0 string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationStateOriginReceipt/%s/%s",
		c.Deployment,
		c.AppName,
		keyID,
		strings.ToLower(pcr0),
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

// migrationChallengeParam: the live challenge published by a predecessor.
func (c *Config) migrationChallengeParam(sourcePCR0 string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationChallenge/%s", c.Deployment, c.AppName, strings.ToLower(sourcePCR0),
	)
}

// migrationResponseParam identifies a candidate or operator response.
func (c *Config) migrationResponseParam(sourcePCR0, responder string) string {
	return fmt.Sprintf(
		"/%s/%s/MigrationResponse/%s/%s",
		c.Deployment,
		c.AppName,
		strings.ToLower(sourcePCR0),
		strings.ToLower(responder),
	)
}

// nonOverridableEnv lists vars the SSM env overlay must never set: they name the
// SSM namespace or the managed-secret set, or they decide the security posture.
// ENCLAVE_DEV selects the KMS lock posture, both Object Lock retentions, the
// intent write timeout and the clock-sync interval. Skipping COSE verification
// requires ENCLAVE_INSECURE_VERIFY_SKIPPED=true and is only allowed in dev mode
// for QEMU tests. The cooldown and clock-source assertion are independently
// configurable in either mode. These settings and the predecessor commitment
// must be baked into the measured image, never supplied by the overlay.
var nonOverridableEnv = map[string]bool{
	"ENCLAVE_DEPLOYMENT":              true,
	"ENCLAVE_APP_NAME":                true,
	"ENCLAVE_SECRETS_CONFIG":          true,
	"ENCLAVE_DEV":                     true,
	"ENCLAVE_MIGRATION_COOLDOWN":      true,
	"ENCLAVE_VERIFY_CLOCK_SOURCE":     true,
	"ENCLAVE_INSECURE_VERIFY_SKIPPED": true,
	"ENCLAVE_PREVIOUS_PCR0":           true,
}

func ApplyEnvOverrides(ctx context.Context, cfg *Config, ssm SSM) error {
	prefix := fmt.Sprintf("/%s/%s/env/", cfg.Deployment, cfg.AppName)

	params, err := ssm.ListParams(ctx, prefix)
	if err != nil {
		return fmt.Errorf("failed to list env override SSM params: %w", err)
	}

	applied := 0
	for _, p := range params {
		key := strings.TrimPrefix(p.Name, prefix)
		// Defensive: skip empty or nested keys so a misconfigured SSM
		// tree can't surface unexpected env var names.
		if key == "" || strings.ContainsRune(key, '/') {
			continue
		}

		// Never let SSM overlay change EIF-baked identity or security knobs.
		if nonOverridableEnv[key] {
			slog.Warn("ignoring non-overridable env var from SSM overlay", "key", key)
			continue
		}

		nextCfg := *cfg
		if err := nextCfg.applyEnvOverride(key, p.Value); err != nil {
			return fmt.Errorf("apply env override %s: %w", key, err)
		}
		if err := safeSetenv(key, p.Value); err != nil {
			return fmt.Errorf("setenv %s: %w", key, err)
		}
		*cfg = nextCfg
		applied++
	}

	slog.Info("env overrides applied", "count", applied, "prefix", prefix)

	return nil
}

func envDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func IsDev() bool {
	if v := strings.TrimSpace(os.Getenv("ENCLAVE_DEV")); v != "" {
		return strings.EqualFold(v, "true")
	}
	return false
}

func getStaticSecretsConfig() string {
	return os.Getenv("ENCLAVE_SECRETS_CONFIG")
}

func getDeployment() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT"))
}

func getAppName() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME"))
}

func getPreviousPCR0() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_PREVIOUS_PCR0"))
}

func getAppPort() string {
	return envDefault("ENCLAVE_APP_PORT", "7074")
}

func getAppBinaryName() string {
	return envDefault("APP_BINARY_NAME", "app")
}

func getFQDN() string {
	return envDefault("ENCLAVE_FQDN", "localhost")
}

func getUpstreamProtocol() string {
	return strings.ToLower(envDefault("ENCLAVE_UPSTREAM", "auto"))
}

func logShipInterval() time.Duration {
	value := envDefault("ENCLAVE_LOG_SHIP_INTERVAL", defaultLogShipInterval.String())
	interval, err := time.ParseDuration(value)
	if err != nil || interval <= 0 {
		return defaultLogShipInterval
	}
	return interval
}

func logRetentionDays() int32 {
	value := envDefault(
		"ENCLAVE_LOG_RETENTION_DAYS", strconv.FormatInt(int64(defaultLogRetentionDays), 10),
	)
	days, err := strconv.ParseInt(value, 10, 32)
	if err != nil || days <= 0 {
		return defaultLogRetentionDays
	}
	return int32(days)
}

func logGroupPrefix() string {
	return normalizeLogGroupPrefix(os.Getenv("ENCLAVE_LOG_GROUP_PREFIX"))
}

func normalizeLogGroupPrefix(raw string) string {
	return path.Join("/", strings.TrimSpace(raw))
}

func migrationCooldown() (time.Duration, bool, error) {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
	if v == "" {
		return 0, false, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, false, fmt.Errorf("invalid ENCLAVE_MIGRATION_COOLDOWN %q: %w", v, err)
	}
	if d < 0 {
		return 0, false, fmt.Errorf("ENCLAVE_MIGRATION_COOLDOWN must not be negative")
	}
	return d, true, nil
}

func verifyClockSource() (bool, bool, error) {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_VERIFY_CLOCK_SOURCE"))
	if v == "" {
		return false, false, nil
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		return false, false, fmt.Errorf("invalid ENCLAVE_VERIFY_CLOCK_SOURCE %q: %w", v, err)
	}
	return enabled, true, nil
}

func insecureVerifySkipped() (bool, bool, error) {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_INSECURE_VERIFY_SKIPPED"))
	if v == "" {
		return false, false, nil
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		return false, false, fmt.Errorf("invalid ENCLAVE_INSECURE_VERIFY_SKIPPED %q: %w", v, err)
	}
	return enabled, true, nil
}
