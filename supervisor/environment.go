package supervisor

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Single home for the supervisor's business-config env reads.
// Infrastructure boilerplate (AWS endpoints, gvproxy/IMDS, lifecycle
// config, cmd-level) stays with its consumer.

func getDeployment() string {
	if d := strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT")); d != "" {
		return d
	}
	return "dev"
}

func getAppName() string {
	if name := strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME")); name != "" {
		return name
	}
	return "app"
}

func getRegion() string {
	if r := strings.TrimSpace(os.Getenv("ENCLAVE_AWS_REGION")); r != "" {
		return r
	}
	return "us-east-1"
}

// getMigrationCooldown returns 0 on unset; surfaces parse errors so the
// caller can fail boot on a malformed value.
func getMigrationCooldown() (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv("ENCLAVE_MIGRATION_COOLDOWN"))
	if v == "" {
		return 0, nil
	}
	return time.ParseDuration(v)
}

func getSupervisorAddr() string {
	if a := strings.TrimSpace(os.Getenv("ENCLAVE_SUPERVISOR_ADDR")); a != "" {
		return a
	}
	return "127.0.0.1:8443"
}

// ssmParamPath returns /<deployment>/<app>/<name>.
func ssmParamPath(name string) string {
	return fmt.Sprintf("/%s/%s/%s", getDeployment(), getAppName(), name)
}
