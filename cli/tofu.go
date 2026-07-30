package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// tofuVars represents the variables passed to OpenTofu via terraform.tfvars.json.
type tofuVars struct {
	Region         string         `json:"region"`
	Account        string         `json:"account"`
	Deployment     string         `json:"deployment"`
	AppName        string         `json:"app_name"`
	InstanceType   string         `json:"instance_type"`
	Local          bool           `json:"local"`
	Secrets        []SecretConfig `json:"secrets"`
	IsKMSKeyLocked bool           `json:"is_kms_key_locked"`

	// GitHub Release coordinates for build artifacts (EIF, supervisor).
	GithubOwner string `json:"github_owner"`
	GithubRepo  string `json:"github_repo"`
	ReleaseTag  string `json:"release_tag"`
	GithubToken string `json:"github_token,omitempty"`

	// Local artifact overrides (skip GitHub download when set).
	EIFPath              string `json:"eif_path,omitempty"`
	SupervisorBinaryPath string `json:"supervisor_binary_path,omitempty"`

	// TLS settings for the enclave's public HTTPS listener, applied at
	// deploy time (tofu stores them in SSM; the runtime reads them at boot).
	TLS tofuTLSVars `json:"tls"`
}

// tofuTLSVars mirrors enclave.yaml's tls: block for the OpenTofu module.
type tofuTLSVars struct {
	FQDN          string `json:"fqdn"`
	Provider      string `json:"provider"`
	Email         string `json:"email"`
	Route53ZoneID string `json:"route53_zone_id"`
}

// tofuDir returns the absolute path to the tofu/ directory at the repo root.
func tofuDir(root string) string {
	return filepath.Join(root, "tofu")
}

// writeTofuVars writes the terraform.tfvars.json file from the config.
//
// When remote is true, EIFPath and SupervisorBinaryPath are left empty so
// the tofu module's null_resource.download_artifacts pulls image.eif and
// supervisor from the GitHub Release at apply time
// (see cli/tofu_files.go: locals.use_local). The github_owner/github_repo/
// release_tag fields supply the URL coordinates.
func writeTofuVars(cfg *Config, root string, remote bool) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repo root: %w", err)
	}

	vars := tofuVars{
		Region:         cfg.Region,
		Account:        cfg.Account,
		Deployment:     cfg.Deployment,
		AppName:        cfg.Name,
		InstanceType:   cfg.InstanceType,
		Local:          os.Getenv("LOCAL_DEPLOYMENT") == "true",
		Secrets:        cfg.Secrets,
		IsKMSKeyLocked: cfg.IsKMSKeyLocked,

		GithubOwner: cfg.App.NixOwner,
		GithubRepo:  cfg.App.NixRepo,
		ReleaseTag:  cfg.App.ReleaseTag,

		TLS: tofuTLSVars{
			FQDN:          cfg.TLS.FQDN,
			Provider:      cfg.TLS.Provider,
			Email:         cfg.TLS.Email,
			Route53ZoneID: cfg.TLS.Route53ZoneID,
		},
	}

	if !remote {
		// Local mode: point tofu at the artifacts produced by `enclave build`.
		vars.EIFPath = filepath.Join(absRoot, ".enclave", "artifacts", "image.eif")
		vars.SupervisorBinaryPath = filepath.Join(absRoot, ".enclave", "artifacts", "supervisor")
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

// backendOverride lets the operator (via interactive prompts or CI flags)
// supply non-default values for the state bucket / lock table / region.
// A nil override means "use the computed defaults."
type backendOverride struct {
	bucket string
	table  string
	region string
}

// defaultBackendValues returns the bucket/table/region computed from
// enclave.yaml. Used as defaults in prompts and as the fallback when the
// operator hasn't overridden anything.
func defaultBackendValues(cfg *Config) (bucket, table, region string) {
	bucket = fmt.Sprintf("%s-%s-tfstate-%s-%s", cfg.Deployment, cfg.Name, cfg.Account, cfg.Region)
	table = fmt.Sprintf("%s-%s-tfstate-lock", cfg.Deployment, cfg.Name)
	region = cfg.Region
	return
}

// writeBackendConfig writes tofu/backend.tf with the S3 + DynamoDB-lock
// settings, defaulting to values computed from enclave.yaml. Pass a non-nil
// override to substitute operator-chosen values. Skip-if-exists so operator
// customizations (assume_role, custom workspace keys, etc.) survive re-runs.
func writeBackendConfig(cfg *Config, root string, override *backendOverride) error {
	local := os.Getenv("LOCAL_DEPLOYMENT") == "true"
	if local || cfg.Account == "" {
		return nil
	}
	backendPath := filepath.Join(tofuDir(root), "backend.tf")
	if _, err := os.Stat(backendPath); err == nil {
		return nil
	}
	bucket, table, region := defaultBackendValues(cfg)
	if override != nil {
		if override.bucket != "" {
			bucket = override.bucket
		}
		if override.table != "" {
			table = override.table
		}
		if override.region != "" {
			region = override.region
		}
	}
	backendCfg := fmt.Sprintf(`# Auto-generated by enclave tofu init — delete and re-run to refresh.
terraform {
  backend "s3" {
    bucket         = %q
    key            = "terraform.tfstate"
    region         = %q
    dynamodb_table = %q
  }
}
`, bucket, region, table)
	if err := os.WriteFile(backendPath, []byte(backendCfg), 0644); err != nil {
		return fmt.Errorf("write backend.tf: %w", err)
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
// It also caches the result to tofu/tofu-outputs.json for offline reads.
func loadTofuOutputs(root string) (TofuOutputs, error) {
	return loadTofuOutputsContext(context.Background(), root)
}

func loadTofuOutputsContext(ctx context.Context, root string) (TofuOutputs, error) {
	dir := tofuDir(root)

	cmd := exec.CommandContext(ctx, "tofu", "-chdir="+dir, "output", "-json")
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("read tofu outputs: %w", ctx.Err())
		}
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
	cachePath := filepath.Join(tofuDir(root), "tofu-outputs.json")
	_ = os.WriteFile(cachePath, cacheData, 0644)

	return outputs, nil
}

// loadCachedTofuOutputs reads the cached tofu-outputs.json file.
func loadCachedTofuOutputs(root string) (TofuOutputs, error) {
	data, err := os.ReadFile(filepath.Join(tofuDir(root), "tofu-outputs.json"))
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
