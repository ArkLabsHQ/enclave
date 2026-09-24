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

// Configuration input names shared by the environment loader and SSM overlay.
const (
	// Application and identity.
	envDeployment        = "ENCLAVE_DEPLOYMENT"
	envAppName           = "ENCLAVE_APP_NAME"
	envAppPort           = "ENCLAVE_APP_PORT"
	envAppBinaryName     = "APP_BINARY_NAME"
	envPreviousPCR0      = "ENCLAVE_PREVIOUS_PCR0"
	envSecretsConfig     = "ENCLAVE_SECRETS_CONFIG"
	envOverrideAllowList = "ENCLAVE_OVERRIDE_ALLOWLIST"

	// Security and migration.
	envDev                   = "ENCLAVE_DEV"
	envInsecureVerifySkipped = "ENCLAVE_INSECURE_VERIFY_SKIPPED"
	envVerifyClockSource     = "ENCLAVE_VERIFY_CLOCK_SOURCE"
	envMigrationCooldown     = "ENCLAVE_MIGRATION_COOLDOWN"

	// Networking and telemetry.
	envFQDN             = "ENCLAVE_FQDN"
	envUpstream         = "ENCLAVE_UPSTREAM"
	envViproxyInAddrs   = "ENCLAVE_VIPROXY_IN_ADDRS"
	envViproxyOutAddrs  = "ENCLAVE_VIPROXY_OUT_ADDRS"
	envLogShipInterval  = "ENCLAVE_LOG_SHIP_INTERVAL"
	envLogRetentionDays = "ENCLAVE_LOG_RETENTION_DAYS"
	envLogGroupPrefix   = "ENCLAVE_LOG_GROUP_PREFIX"

	// ACME settings accepted by the SSM overlay.
	envUseACME       = "ENCLAVE_USE_ACME"
	envACMEDirectory = "ENCLAVE_ACME_DIRECTORY"
	envACMEEmail     = "ENCLAVE_ACME_EMAIL"
	envACMECA        = "ENCLAVE_ACME_CA"

	// AWS configuration.
	envAWSRegion           = "ENCLAVE_AWS_REGION"
	envEC2MetadataEndpoint = "AWS_EC2_METADATA_SERVICE_ENDPOINT"
	envRoute53Endpoint     = "AWS_ENDPOINT_URL_ROUTE53"
	envKMSEndpoint         = "AWS_ENDPOINT_URL_KMS"
	envSSMEndpoint         = "AWS_ENDPOINT_URL_SSM"
	envSTSEndpoint         = "AWS_ENDPOINT_URL_STS"
	envS3Endpoint          = "AWS_ENDPOINT_URL_S3"
	envCloudWatchEndpoint  = "AWS_ENDPOINT_URL_LOGS"
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

	defaultMigrationCooldown = 24 * time.Hour
	defaultLogShipInterval   = 10 * time.Second
	defaultLogRetentionDays  = int32(30)
	logGroupRoot             = "enclave"

	logGroupNameChars = "._-/#"

	migrationPollInterval    = 5 * time.Second
	migrationChallengeRotate = time.Minute

	migrationAbortResponse = "abort"

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

	defaultViproxyIn  = "127.0.0.1:80"
	defaultViproxyOut = "3:8002"
	// Default IMDS proxy: 127.0.0.1:80 -> vsock 3:8002.
	defaultIMDSEndpoint = "http://127.0.0.1:80"
	defaultAWSRegion    = "us-east-1"
	defaultFQDN         = "localhost"
	defaultAppName      = "app"
)

// Config holds runtime HTTP/network settings, the enclave's identity, and the
// security settings the measured image settles rather than an operator.
type Config struct {
	// Identity. EIF-baked and part of PCR0, so it cannot change once loaded —
	// which is the point: every SSM path is derived from these, and a later
	// os.Setenv (the SSM overlay, or a static secret's env var) must not be able
	// to move the namespace out from under a running enclave.
	Deployment         string
	AppName            string
	AppPort            string
	AppBinaryName      string
	PreviousPCR0       string
	StaticSecretConfig string

	// AWS config, EIF-baked and only overridable via in dev mode
	Route53Endpoint     string
	KMSEndpoint         string
	SSMEndpoint         string
	STSEndpoint         string
	S3Endpoint          string
	CloudWatchEndpoint  string
	AWSRegion           string
	EC2MetadataEndpoint string

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
	ViproxyInAddr    string
	ViproxyOutAddr   string

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

	OverrideAllowList map[string]bool
	ChildEnv          map[string]string
}

// LoadConfig captures runtime configuration and unsets each environment variable
// it reads.
func LoadConfig() (*Config, error) {
	// Point the reverse proxy directly at the user app.
	appPort := takeEnvDefault(envAppPort, "7074")
	appWebSrv, err := url.Parse("http://127.0.0.1:" + appPort)
	if err != nil {
		return nil, fmt.Errorf("parse app web srv url: %w", err)
	}

	cfg := &Config{
		Deployment:         takeEnv(envDeployment),
		AppName:            takeEnv(envAppName),
		AppBinaryName:      takeEnvDefault(envAppBinaryName, defaultAppName),
		AppPort:            appPort,
		PreviousPCR0:       takeEnv(envPreviousPCR0),
		StaticSecretConfig: takeEnv(envSecretsConfig),
		EC2MetadataEndpoint: takeEnvDefault(
			envEC2MetadataEndpoint,
			defaultIMDSEndpoint,
		),
		Route53Endpoint:       takeEnv(envRoute53Endpoint),
		KMSEndpoint:           takeEnv(envKMSEndpoint),
		SSMEndpoint:           takeEnv(envSSMEndpoint),
		STSEndpoint:           takeEnv(envSTSEndpoint),
		S3Endpoint:            takeEnv(envS3Endpoint),
		CloudWatchEndpoint:    takeEnv(envCloudWatchEndpoint),
		AWSRegion:             takeEnvDefault(envAWSRegion, defaultAWSRegion),
		ViproxyInAddr:         takeEnvDefault(envViproxyInAddrs, defaultViproxyIn),
		ViproxyOutAddr:        takeEnvDefault(envViproxyOutAddrs, defaultViproxyOut),
		FQDN:                  takeEnvDefault(envFQDN, defaultFQDN),
		ExtPort:               extPort,
		IntPort:               intPort,
		HostProxyPort:         hostProxyPort,
		AppWebSrv:             appWebSrv,
		UpstreamProtocol:      strings.ToLower(takeEnvDefault(envUpstream, "auto")),
		LogShipInterval:       logShipInterval(),
		LogRetentionDays:      logRetentionDays(),
		LogGroupPrefix:        normalizeLogGroupPrefix(takeEnv(envLogGroupPrefix)),
		GenesisRetention:      prodRetention,
		IntentRetention:       prodRetention,
		IntentWriteTimeout:    prodIntentWriteTimeout,
		MigrationCooldown:     defaultMigrationCooldown,
		ClockSyncInterval:     prodClockSyncInterval,
		VerifyClockSource:     takeEnv(envVerifyClockSource) != "false",
		InsecureVerifySkipped: false,
		KMSLocked:             true,
		OverrideAllowList:     make(map[string]bool),
		ChildEnv:              make(map[string]string),
	}

	if takeEnv(envDev) == "true" {
		cfg.KMSLocked = false
		cfg.GenesisRetention = devGenesisRetention
		cfg.IntentRetention = devIntentRetention
		cfg.IntentWriteTimeout = devIntentWriteTimeout
		cfg.ClockSyncInterval = devClockSyncInterval

		// only allow overriding cfg.InsecureVerifySkipped in dev mode
		// It is false by default unless explicitly overridden
		cfg.InsecureVerifySkipped = takeEnv(envInsecureVerifySkipped) == "true"
	}

	if cooldown := takeEnv(envMigrationCooldown); cooldown != "" {
		d, err := time.ParseDuration(cooldown)
		if err != nil {
			return nil, fmt.Errorf("invalid ENCLAVE_MIGRATION_COOLDOWN %q: %w", cooldown, err)
		}
		if d < 0 {
			return nil, fmt.Errorf("ENCLAVE_MIGRATION_COOLDOWN must not be negative")
		}

		cfg.MigrationCooldown = d
	}

	for v := range strings.SplitSeq(takeEnv(envOverrideAllowList), ",") {
		cfg.OverrideAllowList[strings.TrimSpace(v)] = true
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

func (c *Config) ApplySSMOverlay(ctx context.Context, ssm SSM) error {
	prefix := fmt.Sprintf("/%s/%s/env/", c.Deployment, c.AppName)

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

		switch key {
		case envAppPort:
			port, err := strconv.ParseUint(p.Value, 10, 16)
			if err != nil || port == 0 {
				return fmt.Errorf("invalid application port %q", p.Value)
			}
			appWebSrv, err := url.Parse("http://127.0.0.1:" + p.Value)
			if err != nil {
				return fmt.Errorf("parse app web srv url: %w", err)
			}
			c.AppPort = p.Value
			c.AppWebSrv = appWebSrv
		case envFQDN:
			c.FQDN = p.Value
		case envUseACME:
			c.UseACME = strings.EqualFold(p.Value, "true")
		case envACMEDirectory:
			c.ACMEDirectory = p.Value
		case envACMEEmail:
			c.ACMEEmail = p.Value
		case envACMECA:
			c.ACMECA = p.Value
		case envLogGroupPrefix:
			c.LogGroupPrefix = normalizeLogGroupPrefix(p.Value)
			if err := c.validateLogGroupPrefix(); err != nil {
				return err
			}
		// key is not an overridable env var, check if overriding is allowed by the app
		default:
			if _, allowed := c.OverrideAllowList[key]; !allowed {
				slog.Warn("ignoring non-overridable env var from SSM overlay", "key", key)
				continue
			}

			c.ChildEnv[key] = p.Value
		}
		applied++
	}

	slog.Info("env overrides applied", "count", applied, "prefix", prefix)

	return nil
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

// takeEnv consumes a configuration variable, removing it from the process environment.
func takeEnv(key string) string {
	value := os.Getenv(key)
	_ = os.Unsetenv(key)
	return strings.TrimSpace(value)
}

func takeEnvDefault(key, fallback string) string {
	if v := takeEnv(key); v != "" {
		return v
	}
	return fallback
}

func logShipInterval() time.Duration {
	value := takeEnvDefault(envLogShipInterval, defaultLogShipInterval.String())
	interval, err := time.ParseDuration(value)
	if err != nil || interval <= 0 {
		return defaultLogShipInterval
	}
	return interval
}

func logRetentionDays() int32 {
	value := takeEnvDefault(
		envLogRetentionDays, strconv.FormatInt(int64(defaultLogRetentionDays), 10),
	)
	days, err := strconv.ParseInt(value, 10, 32)
	if err != nil || days <= 0 {
		return defaultLogRetentionDays
	}
	return int32(days)
}

func normalizeLogGroupPrefix(raw string) string {
	return path.Join("/", strings.TrimSpace(raw))
}
