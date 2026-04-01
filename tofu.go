package introspector_enclave

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// runCmd runs an external command with the given environment, streaming
// stdout/stderr to the terminal. Returns an error if the command fails.
func runCmd(name string, args []string, dir string, env []string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

// tofuVars represents the variables passed to OpenTofu via terraform.tfvars.json.
type tofuVars struct {
	Region            string         `json:"region"`
	Account           string         `json:"account"`
	Deployment        string         `json:"deployment"`
	AppName           string         `json:"app_name"`
	InstanceType      string         `json:"instance_type"`
	Local             bool           `json:"local"`
	Secrets           []SecretConfig `json:"secrets"`
	MigrationCooldown string         `json:"migration_cooldown"`
	PreviousPCR0      string         `json:"previous_pcr0"`
	ExpectedPCR0      string         `json:"expected_pcr0,omitempty"`

	// GitHub Release coordinates for build artifacts (EIF, mgmt, gvproxy).
	GithubOwner string `json:"github_owner"`
	GithubRepo  string `json:"github_repo"`
	ReleaseTag  string `json:"release_tag"`
	GithubToken string `json:"github_token,omitempty"`

	// Local artifact overrides (skip GitHub download when set).
	EIFPath           string `json:"eif_path,omitempty"`
	MgmtBinaryPath    string `json:"mgmt_binary_path,omitempty"`
	GvproxyBinaryPath string `json:"gvproxy_binary_path,omitempty"`

	// Local asset file paths (scripts, systemd units — scaffolded by enclave init).
	EnclaveInitScriptPath string `json:"enclave_init_script_path"`
	WatchdogServicePath   string `json:"watchdog_service_path"`
	IMDSProxyServicePath  string `json:"imds_proxy_service_path"`
	GvproxyServicePath    string `json:"gvproxy_service_path"`
	MgmtServicePath       string `json:"mgmt_service_path"`
}

// tofuDir returns the absolute path to the enclave/tofu/ directory.
func tofuDir(root string) string {
	return filepath.Join(root, "enclave", "tofu")
}

// writeTofuVars writes the terraform.tfvars.json file from the config.
func writeTofuVars(cfg *Config, root string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repo root: %w", err)
	}

	vars := tofuVars{
		Region:            cfg.Region,
		Account:           cfg.Account,
		Deployment:        cfg.Prefix,
		AppName:           cfg.Name,
		InstanceType:      cfg.InstanceType,
		Local:             os.Getenv("LOCAL_DEPLOYMENT") == "true",
		Secrets:           cfg.Secrets,
		MigrationCooldown: cfg.MigrationCooldown,
		PreviousPCR0:      cfg.PreviousPCR0,
		ExpectedPCR0:      readPCR0FromArtifacts(absRoot),

		GithubOwner: cfg.App.NixOwner,
		GithubRepo:  cfg.App.NixRepo,
		ReleaseTag:  "eif-latest",

		// CLI builds artifacts locally — use local paths, skip GitHub download.
		EIFPath:           filepath.Join(absRoot, "enclave", "artifacts", "image.eif"),
		MgmtBinaryPath:    filepath.Join(absRoot, "enclave", "artifacts", "enclave-mgmt"),
		GvproxyBinaryPath: filepath.Join(absRoot, "enclave", "artifacts", "gvproxy"),

		EnclaveInitScriptPath: filepath.Join(absRoot, "enclave", "scripts", "enclave_init.sh"),
		WatchdogServicePath:   filepath.Join(absRoot, "enclave", "systemd", "enclave-watchdog.service"),
		IMDSProxyServicePath:  filepath.Join(absRoot, "enclave", "systemd", "enclave-imds-proxy.service"),
		GvproxyServicePath:    filepath.Join(absRoot, "enclave", "systemd", "gvproxy.service"),
		MgmtServicePath:       filepath.Join(absRoot, "enclave", "systemd", "enclave-mgmt.service"),
	}

	data, err := json.MarshalIndent(vars, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tfvars: %w", err)
	}

	tfvarsPath := filepath.Join(tofuDir(root), "terraform.tfvars.json")
	if err := os.WriteFile(tfvarsPath, data, 0644); err != nil {
		return fmt.Errorf("write tfvars: %w", err)
	}
	return nil
}

// TofuOutputs represents the parsed output from tofu output -json.
// Keys are output names, values are the output values as strings.
type TofuOutputs map[string]string

// tofuOutputJSON is the raw JSON structure from tofu output -json.
type tofuOutputJSON map[string]struct {
	Value interface{} `json:"value"`
	Type  interface{} `json:"type"`
}

// loadTofuOutputs runs tofu output -json and parses the result.
// It also caches the result to enclave/tofu-outputs.json for offline reads.
func loadTofuOutputs(root string) (TofuOutputs, error) {
	dir := tofuDir(root)

	cmd := exec.Command("tofu", "-chdir="+dir, "output", "-json")
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		// Fall back to cached outputs.
		return loadCachedTofuOutputs(root)
	}

	var raw tofuOutputJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse tofu output: %w", err)
	}

	outputs := make(TofuOutputs)
	for k, v := range raw {
		outputs[k] = fmt.Sprintf("%v", v.Value)
	}

	// Cache for offline reads.
	cacheData, _ := json.MarshalIndent(outputs, "", "  ")
	cachePath := filepath.Join(root, "enclave", "tofu-outputs.json")
	_ = os.WriteFile(cachePath, cacheData, 0644)

	return outputs, nil
}

// loadCachedTofuOutputs reads the cached tofu-outputs.json file.
func loadCachedTofuOutputs(root string) (TofuOutputs, error) {
	data, err := os.ReadFile(filepath.Join(root, "enclave", "tofu-outputs.json"))
	if err != nil {
		return nil, fmt.Errorf("cannot read tofu outputs: %w (run 'tofu apply' first)", err)
	}
	var outputs TofuOutputs
	if err := json.Unmarshal(data, &outputs); err != nil {
		return nil, fmt.Errorf("invalid tofu-outputs.json: %w", err)
	}
	return outputs, nil
}

// getOutput reads a value from OpenTofu outputs.
func (o TofuOutputs) getOutput(key string) string {
	return o[key]
}

// readPCR0FromArtifacts reads PCR0 from enclave/artifacts/pcr.json if it exists.
// Returns empty string if the file is missing (e.g. before first build).
func readPCR0FromArtifacts(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "enclave", "artifacts", "pcr.json"))
	if err != nil {
		return ""
	}
	var pcrs struct {
		PCR0 string `json:"PCR0"`
	}
	if json.Unmarshal(data, &pcrs) != nil {
		return ""
	}
	return pcrs.PCR0
}

