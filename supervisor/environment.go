package supervisor

import (
	"fmt"
	"os"
	"strings"
)

// Single home for the supervisor's business-config env reads.
// Infrastructure boilerplate (AWS endpoints, gvproxy/IMDS, lifecycle
// config, cmd-level) stays with its consumer.

// validateEnvironment rejects unusable settings before any caller runs; New
// gates on it.
func validateEnvironment() error {
	if getDeployment() == "" {
		return fmt.Errorf("ENCLAVE_DEPLOYMENT must be set: it namespaces all SSM state")
	}
	if getAppName() == "" {
		return fmt.Errorf("ENCLAVE_APP_NAME must be set: it namespaces all SSM state")
	}
	return nil
}

func getDeployment() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOYMENT"))
}

func getAppName() string {
	return strings.TrimSpace(os.Getenv("ENCLAVE_APP_NAME"))
}

func getRegion() string {
	if r := strings.TrimSpace(os.Getenv("ENCLAVE_AWS_REGION")); r != "" {
		return r
	}
	return "us-east-1"
}

func getSupervisorAddr() string {
	if a := strings.TrimSpace(os.Getenv("ENCLAVE_SUPERVISOR_ADDR")); a != "" {
		return a
	}
	return "127.0.0.1:8443"
}

// kmsKeyLocked mirrors the runtime: the EIF's lock posture, plumbed to the host
// supervisor via user_data.
func kmsKeyLocked() bool {
	return os.Getenv("ENCLAVE_KMS_KEY_LOCKED") == "true"
}

func lockSegment() string {
	if kmsKeyLocked() {
		return "locked"
	}
	return "unlocked"
}

// kmsSubtreeParamPath returns /<deployment>/<app>/<lock>/<name> for KMS state.
func kmsSubtreeParamPath(name string) string {
	return fmt.Sprintf("/%s/%s/%s/%s", getDeployment(), getAppName(), lockSegment(), name)
}
