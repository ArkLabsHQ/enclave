# Root module variables — pass-through to sub-modules.
# These are populated by the Go CLI via terraform.tfvars.json,
# or by company CI pipelines via -var flags or .tfvars files.

variable "region" {
  description = "AWS region for all resources."
  type        = string
}

variable "account" {
  description = "AWS account ID (12 digits)."
  type        = string
}

variable "deployment" {
  description = "Deployment prefix (e.g. dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "app_name" {
  description = "Application name from enclave.yaml."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for the Nitro Enclave host."
  type        = string
  default     = "m6i.xlarge"
}

variable "local" {
  description = "When true, skip VPC/EC2/ECR resources (localstack mode)."
  type        = bool
  default     = false
}

variable "secrets" {
  description = "List of secrets managed by KMS inside the enclave."
  type = list(object({
    name    = string
    env_var = string
  }))
  default = []
}

variable "migration_cooldown" {
  description = "Migration cooldown duration string."
  type        = string
  default     = "0s"
}

variable "previous_pcr0" {
  description = "Previous PCR0 hash for migration chain validation."
  type        = string
  default     = "genesis"
}

variable "expected_pcr0" {
  description = "Expected PCR0 of the current EIF (from pcr.json). Used to trigger migrations."
  type        = string
  default     = ""
}

variable "mgmt_url" {
  description = "Management server URL for local mode migrations."
  type        = string
  default     = "http://localhost:8444"
}

# --- GitHub Release artifacts ---

variable "github_owner" {
  description = "GitHub repository owner (e.g. ArkLabsHQ)."
  type        = string
  default     = ""
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
  default     = ""
}

variable "release_tag" {
  description = "GitHub Release tag to fetch artifacts from."
  type        = string
  default     = "eif-latest"
}

variable "github_token" {
  description = "GitHub token for private repo access (optional for public repos)."
  type        = string
  default     = ""
  sensitive   = true
}

# --- Local artifact overrides ---
# When set, these skip the GitHub Release download and use local files directly.
# Used by enclave deploy (CLI builds artifacts locally) and integration tests.

variable "eif_path" {
  description = "Local path to image.eif. Overrides GitHub Release download."
  type        = string
  default     = ""
}

variable "mgmt_binary_path" {
  description = "Local path to enclave-mgmt binary. Overrides GitHub Release download."
  type        = string
  default     = ""
}

variable "gvproxy_binary_path" {
  description = "Local path to gvproxy binary. Overrides GitHub Release download."
  type        = string
  default     = ""
}

# --- Local asset file paths ---

variable "enclave_init_script_path" {
  description = "Local path to enclave_init.sh."
  type        = string
}

variable "watchdog_service_path" {
  description = "Local path to enclave-watchdog.service."
  type        = string
}

variable "imds_proxy_service_path" {
  description = "Local path to enclave-imds-proxy.service."
  type        = string
}

variable "gvproxy_service_path" {
  description = "Local path to gvproxy.service."
  type        = string
}

variable "gvproxy_start_script_path" {
  description = "Local path to gvproxy start.sh script."
  type        = string
}

variable "mgmt_service_path" {
  description = "Local path to enclave-mgmt.service."
  type        = string
}
