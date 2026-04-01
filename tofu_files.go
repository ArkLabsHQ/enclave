package introspector_enclave

// OpenTofu files scaffolded by `enclave init`.
// Generated from enclave/tofu/ — do not edit by hand.

const tofuRootMain = `# Root module for the enclave CLI.
# Calls the reusable enclave module.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Configured dynamically via -backend-config flags from the Go CLI.
  # For standalone usage, see examples/standalone/backend.tf instead.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      ManagedBy  = "opentofu"
      Deployment = var.deployment
      AppName    = var.app_name
    }
  }
}

# The enclave stack: KMS, IAM, VPC, EC2, SSM, S3.
module "enclave" {
  source = "./modules/enclave"

  region            = var.region
  account           = var.account
  deployment        = var.deployment
  app_name          = var.app_name
  instance_type     = var.instance_type
  local             = var.local
  secrets           = var.secrets
  migration_cooldown = var.migration_cooldown
  previous_pcr0     = var.previous_pcr0
  expected_pcr0     = var.expected_pcr0
  mgmt_url          = var.mgmt_url
  github_owner  = var.github_owner
  github_repo   = var.github_repo
  release_tag   = var.release_tag
  github_token  = var.github_token

  eif_path            = var.eif_path
  mgmt_binary_path    = var.mgmt_binary_path
  gvproxy_binary_path = var.gvproxy_binary_path

  enclave_init_script_path = var.enclave_init_script_path
  watchdog_service_path    = var.watchdog_service_path
  imds_proxy_service_path  = var.imds_proxy_service_path
  gvproxy_service_path     = var.gvproxy_service_path
  mgmt_service_path        = var.mgmt_service_path
}
`

const tofuRootVariables = `# Root module variables — pass-through to sub-modules.
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

variable "mgmt_service_path" {
  description = "Local path to enclave-mgmt.service."
  type        = string
}
`

const tofuRootOutputs = `# Root module outputs — re-exported from sub-modules.

output "ec2_role_arn" {
  description = "EC2 instance role ARN."
  value       = module.enclave.ec2_role_arn
}

output "kms_key_id" {
  description = "KMS encryption key ID."
  value       = module.enclave.kms_key_id
}

output "instance_id" {
  description = "EC2 instance ID (empty in local mode)."
  value       = module.enclave.instance_id
}

output "elastic_ip" {
  description = "Static public IP for the enclave instance (empty in local mode)."
  value       = module.enclave.elastic_ip
}

output "storage_bucket" {
  description = "S3 storage bucket name."
  value       = module.enclave.storage_bucket
}

`

const tofuModuleEnclaveMain = `terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

locals {
  prefix = "${var.deployment}-${var.app_name}"

  # Availability zones for VPC subnets.
  az_a = "${var.region}a"
  az_b = "${var.region}b"
}
`

const tofuModuleEnclaveVariables = `variable "region" {
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
  description = "When true, skip VPC/EC2 resources (localstack mode)."
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
  description = "Management server URL for local mode migrations (e.g. http://localhost:8444)."
  type        = string
  default     = "http://localhost:8444"
}

# --- GitHub Release artifacts ---
# Build artifacts (EIF, mgmt, gvproxy) are fetched from a GitHub Release
# at apply time using null_resource + curl — unless local path overrides are set.

variable "github_owner" {
  description = "GitHub repository owner."
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

variable "mgmt_service_path" {
  description = "Local path to enclave-mgmt.service."
  type        = string
}
`

const tofuModuleEnclaveOutputs = `output "ec2_role_arn" {
  description = "EC2 instance role ARN."
  value       = aws_iam_role.instance.arn
}

output "kms_key_id" {
  description = "KMS encryption key ID."
  value       = aws_kms_key.encryption.key_id
}

output "instance_id" {
  description = "EC2 instance ID (empty in local mode)."
  value       = var.local ? "" : aws_instance.nitro[0].id
}

output "elastic_ip" {
  description = "Static public IP for the enclave instance (empty in local mode)."
  value       = var.local ? "" : aws_eip.instance[0].public_ip
}

output "storage_bucket" {
  description = "S3 storage bucket name."
  value       = aws_s3_bucket.storage.id
}
`

const tofuModuleEnclaveKMS = `# KMS encryption key for enclave secrets.
#
# The enclave self-applies a PCR0-locked key policy at first boot, removing
# PutKeyPolicy from everyone. After locking, only the enclave (via the mgmt
# server) can schedule key deletion. The instance destroy provisioner handles
# this automatically. The KMS key is then removed from state so tofu destroy
# doesn't try (and fail) to delete it.

resource "aws_kms_key" "encryption" {
  enable_key_rotation = true
  description         = "${local.prefix} enclave encryption key"
}

# Remove KMS key from state on destroy. The key policy is locked to PCR0
# after first boot, so tofu cannot delete it. Key deletion is scheduled
# by the instance's destroy provisioner via the mgmt server.
resource "null_resource" "kms_state_cleanup" {
  triggers = {
    key_id = aws_kms_key.encryption.id
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "tofu state rm aws_kms_key.encryption aws_kms_key_policy.encryption 2>/dev/null || true"
    on_failure = continue
  }
}

# Initial key policy: grants the EC2 instance role encrypt/decrypt + policy
# management. The enclave replaces this policy at runtime with a PCR0-locked
# version via selfApplyKMSPolicy().
resource "aws_kms_key_policy" "encryption" {
  key_id = aws_kms_key.encryption.id

  policy = data.aws_iam_policy_document.kms_key_policy.json
}

data "aws_iam_policy_document" "kms_key_policy" {
  # Allow the account root full key management (required by AWS).
  statement {
    sid    = "AllowRootAccount"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Allow the EC2 instance role to encrypt/decrypt and manage key policy.
  statement {
    sid    = "AllowInstanceRole"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.instance.arn]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
      "kms:PutKeyPolicy",
      "kms:GetKeyPolicy",
    ]
    resources = ["*"]
  }
}
`

const tofuModuleEnclaveIAM = `# IAM role for the EC2 Nitro Enclave host instance.

resource "aws_iam_role" "instance" {
  name_prefix = "${local.prefix}-enclave-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name_prefix = "${local.prefix}-enclave-"
  role        = aws_iam_role.instance.name
}

# SSM managed instance core (remote only — enables SSM Session Manager).
resource "aws_iam_role_policy_attachment" "ssm_core" {
  count      = var.local ? 0 : 1
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Inline policy granting access to all enclave resources.
resource "aws_iam_role_policy" "enclave" {
  name   = "enclave-access"
  role   = aws_iam_role.instance.id
  policy = data.aws_iam_policy_document.enclave.json
}

data "aws_iam_policy_document" "enclave" {
  # S3: read all uploaded assets.
  statement {
    sid = "S3AssetRead"
    actions = [
      "s3:GetObject",
      "s3:GetBucketLocation",
    ]
    resources = concat(
      [aws_s3_bucket.assets.arn],
      [for obj in [
        aws_s3_object.enclave_eif,
        aws_s3_object.enclave_init,
        aws_s3_object.watchdog_systemd,
        aws_s3_object.imds_systemd,
        aws_s3_object.gvproxy_systemd,
        aws_s3_object.mgmt_binary,
        aws_s3_object.mgmt_systemd,
        aws_s3_object.gvproxy_binary,
      ] : "${aws_s3_bucket.assets.arn}/${obj.key}"],
    )
  }

  # S3: read/write on persistent storage bucket.
  statement {
    sid = "S3StorageReadWrite"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      aws_s3_bucket.storage.arn,
      "${aws_s3_bucket.storage.arn}/*",
    ]
  }

  # SSM: read/write on secret ciphertext parameters.
  statement {
    sid = "SSMSecretParams"
    actions = [
      "ssm:GetParameter",
      "ssm:PutParameter",
    ]
    resources = concat(
      [for p in aws_ssm_parameter.secret_ciphertext : p.arn],
      [for p in aws_ssm_parameter.secret_migration : p.arn],
      [
        aws_ssm_parameter.migration_kms_key_id.arn,
        aws_ssm_parameter.migration_previous_pcr0.arn,
        aws_ssm_parameter.migration_previous_pcr0_attestation.arn,
        aws_ssm_parameter.migration_old_kms_key_id.arn,
        aws_ssm_parameter.storage_dek.arn,
        aws_ssm_parameter.migration_storage_dek.arn,
      ],
    )
  }

  # SSM: read-only parameters.
  statement {
    sid     = "SSMReadOnly"
    actions = ["ssm:GetParameter"]
    resources = [
      aws_ssm_parameter.kms_key_id.arn,
      aws_ssm_parameter.storage_bucket_name.arn,
    ]
  }

  # KMS: encrypt/decrypt + policy management.
  statement {
    sid = "KMSAccess"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
      "kms:PutKeyPolicy",
      "kms:GetKeyPolicy",
    ]
    resources = [aws_kms_key.encryption.arn]
  }
}
`

const tofuModuleEnclaveSSM = `# SSM parameters for enclave secrets and migration state.

locals {
  secrets_map = { for s in var.secrets : s.name => s }
}

# Per-secret ciphertext parameters.
resource "aws_ssm_parameter" "secret_ciphertext" {
  for_each = local.secrets_map

  name  = "/${var.deployment}/${var.app_name}/${each.key}/Ciphertext"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

# Per-secret migration ciphertext parameters.
resource "aws_ssm_parameter" "secret_migration" {
  for_each = local.secrets_map

  name  = "/${var.deployment}/${var.app_name}/Migration/${each.key}/Ciphertext"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

# Shared migration parameters (one per deployment, not per secret).

resource "aws_ssm_parameter" "migration_kms_key_id" {
  name  = "/${var.deployment}/${var.app_name}/MigrationKMSKeyID"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "migration_previous_pcr0" {
  name  = "/${var.deployment}/${var.app_name}/MigrationPreviousPCR0"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "migration_previous_pcr0_attestation" {
  name  = "/${var.deployment}/${var.app_name}/MigrationPreviousPCR0Attestation"
  type  = "String"
  tier  = "Advanced"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "migration_old_kms_key_id" {
  name  = "/${var.deployment}/${var.app_name}/MigrationOldKMSKeyID"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

# KMS key ID (auto-populated with the actual key ID).
resource "aws_ssm_parameter" "kms_key_id" {
  name  = "/${var.deployment}/${var.app_name}/KMSKeyID"
  type  = "String"
  value = aws_kms_key.encryption.key_id
}

# Storage bucket name.
resource "aws_ssm_parameter" "storage_bucket_name" {
  name  = "/${var.deployment}/${var.app_name}/StorageBucketName"
  type  = "String"
  value = aws_s3_bucket.storage.id
}

# Storage data encryption key (DEK).
resource "aws_ssm_parameter" "storage_dek" {
  name  = "/${var.deployment}/${var.app_name}/StorageDEK/Ciphertext"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}

# Migration storage DEK.
resource "aws_ssm_parameter" "migration_storage_dek" {
  name  = "/${var.deployment}/${var.app_name}/Migration/StorageDEK/Ciphertext"
  type  = "String"
  value = "UNSET"

  lifecycle {
    ignore_changes = [value]
  }
}
`

const tofuModuleEnclaveS3 = `locals {
  # When local paths are set, use them directly. Otherwise download from GitHub Release.
  use_local      = var.eif_path != ""
  artifacts_dir  = "${path.module}/.artifacts"
  auth_header    = var.github_token != "" ? "-H \"Authorization: Bearer ${var.github_token}\"" : ""
  release_base   = "https://github.com/${var.github_owner}/${var.github_repo}/releases/download/${var.release_tag}"

  eif_source     = local.use_local ? var.eif_path : "${local.artifacts_dir}/image.eif"
  mgmt_source    = local.use_local ? var.mgmt_binary_path : "${local.artifacts_dir}/enclave-mgmt"
  gvproxy_source = local.use_local ? var.gvproxy_binary_path : "${local.artifacts_dir}/gvproxy"
}

# Download build artifacts from GitHub Release (skipped when local paths are set).
resource "null_resource" "download_artifacts" {
  count = local.use_local ? 0 : 1

  triggers = {
    release_tag = var.release_tag
  }

  provisioner "local-exec" {
    command = <<-EOT
      mkdir -p ${local.artifacts_dir}
      curl -sfL ${local.auth_header} -o ${local.artifacts_dir}/image.eif ${local.release_base}/image.eif
      curl -sfL ${local.auth_header} -o ${local.artifacts_dir}/enclave-mgmt ${local.release_base}/enclave-mgmt
      curl -sfL ${local.auth_header} -o ${local.artifacts_dir}/gvproxy ${local.release_base}/gvproxy
    EOT
  }
}

# S3 bucket for enclave deployment assets (EIF, scripts, systemd units, binaries).
# This bucket is ephemeral — force_destroy is always true since assets can be re-uploaded.

resource "aws_s3_bucket" "assets" {
  bucket_prefix = "${local.prefix}-assets-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "enclave_eif" {
  depends_on = [null_resource.download_artifacts]
  bucket     = aws_s3_bucket.assets.id
  key        = "image.eif"
  source     = local.eif_source
  etag       = local.use_local ? filemd5(local.eif_source) : null
}

resource "aws_s3_object" "enclave_init" {
  bucket = aws_s3_bucket.assets.id
  key    = "enclave_init.sh"
  source = var.enclave_init_script_path
  etag   = filemd5(var.enclave_init_script_path)
}

resource "aws_s3_object" "watchdog_systemd" {
  bucket = aws_s3_bucket.assets.id
  key    = "enclave-watchdog.service"
  source = var.watchdog_service_path
  etag   = filemd5(var.watchdog_service_path)
}

resource "aws_s3_object" "imds_systemd" {
  bucket = aws_s3_bucket.assets.id
  key    = "enclave-imds-proxy.service"
  source = var.imds_proxy_service_path
  etag   = filemd5(var.imds_proxy_service_path)
}

resource "aws_s3_object" "gvproxy_systemd" {
  bucket = aws_s3_bucket.assets.id
  key    = "gvproxy.service"
  source = var.gvproxy_service_path
  etag   = filemd5(var.gvproxy_service_path)
}

resource "aws_s3_object" "mgmt_binary" {
  depends_on = [null_resource.download_artifacts]
  bucket     = aws_s3_bucket.assets.id
  key        = "enclave-mgmt"
  source     = local.mgmt_source
  etag       = local.use_local ? filemd5(local.mgmt_source) : null
}

resource "aws_s3_object" "gvproxy_binary" {
  depends_on = [null_resource.download_artifacts]
  bucket     = aws_s3_bucket.assets.id
  key        = "gvproxy"
  source     = local.gvproxy_source
  etag       = local.use_local ? filemd5(local.gvproxy_source) : null
}

resource "aws_s3_object" "mgmt_systemd" {
  bucket = aws_s3_bucket.assets.id
  key    = "enclave-mgmt.service"
  source = var.mgmt_service_path
  etag   = filemd5(var.mgmt_service_path)
}

# Persistent storage bucket for enclave data (Store/Load API).

resource "aws_s3_bucket" "storage" {
  bucket_prefix = "${local.prefix}-storage-"
  force_destroy = var.local
}

resource "aws_s3_bucket_public_access_block" "storage" {
  bucket = aws_s3_bucket.storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "storage_ssl" {
  count  = var.local ? 0 : 1
  bucket = aws_s3_bucket.storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceSSL"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.storage.arn,
        "${aws_s3_bucket.storage.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
`

const tofuModuleEnclaveVPC = `# VPC + networking (remote only — skipped for localstack).

resource "aws_vpc" "main" {
  count = var.local ? 0 : 1

  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.prefix}-vpc" }
}

# Public subnet (for EC2 instance with EIP).
resource "aws_subnet" "public" {
  count = var.local ? 0 : 1

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = "10.0.1.0/24"
  availability_zone = local.az_a

  tags = { Name = "${local.prefix}-public" }
}

# Private subnet (for VPC endpoints and NAT egress).
resource "aws_subnet" "private" {
  count = var.local ? 0 : 1

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = "10.0.2.0/24"
  availability_zone = local.az_a

  tags = { Name = "${local.prefix}-private" }
}

# Second private subnet in AZ-b (some services require multi-AZ).
resource "aws_subnet" "private_b" {
  count = var.local ? 0 : 1

  vpc_id            = aws_vpc.main[0].id
  cidr_block        = "10.0.3.0/24"
  availability_zone = local.az_b

  tags = { Name = "${local.prefix}-private-b" }
}

# Internet gateway for public subnet.
resource "aws_internet_gateway" "main" {
  count  = var.local ? 0 : 1
  vpc_id = aws_vpc.main[0].id

  tags = { Name = "${local.prefix}-igw" }
}

# NAT gateway for private subnet egress.
resource "aws_eip" "nat" {
  count  = var.local ? 0 : 1
  domain = "vpc"

  tags = { Name = "${local.prefix}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  count = var.local ? 0 : 1

  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = { Name = "${local.prefix}-nat" }

  depends_on = [aws_internet_gateway.main]
}

# Route tables.
resource "aws_route_table" "public" {
  count  = var.local ? 0 : 1
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = { Name = "${local.prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = var.local ? 0 : 1
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count  = var.local ? 0 : 1
  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[0].id
  }

  tags = { Name = "${local.prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = var.local ? 0 : 1
  subnet_id      = aws_subnet.private[0].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_route_table_association" "private_b" {
  count          = var.local ? 0 : 1
  subnet_id      = aws_subnet.private_b[0].id
  route_table_id = aws_route_table.private[0].id
}

# VPC endpoints — keep traffic to AWS services inside the VPC.

resource "aws_vpc_endpoint" "kms" {
  count = var.local ? 0 : 1

  vpc_id              = aws_vpc.main[0].id
  service_name        = "com.amazonaws.${var.region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private[0].id, aws_subnet.private_b[0].id]
  private_dns_enabled = true

  tags = { Name = "${local.prefix}-kms-endpoint" }
}

resource "aws_vpc_endpoint" "ssm" {
  count = var.local ? 0 : 1

  vpc_id              = aws_vpc.main[0].id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private[0].id, aws_subnet.private_b[0].id]
  private_dns_enabled = true

  tags = { Name = "${local.prefix}-ssm-endpoint" }
}

resource "aws_vpc_endpoint" "ecr" {
  count = var.local ? 0 : 1

  vpc_id              = aws_vpc.main[0].id
  service_name        = "com.amazonaws.${var.region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private[0].id, aws_subnet.private_b[0].id]
  private_dns_enabled = true

  tags = { Name = "${local.prefix}-ecr-endpoint" }
}

resource "aws_vpc_endpoint" "s3" {
  count = var.local ? 0 : 1

  vpc_id            = aws_vpc.main[0].id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private[0].id]

  tags = { Name = "${local.prefix}-s3-endpoint" }
}
`

const tofuModuleEnclaveEC2 = `# EC2 Nitro Enclave instance (remote only — skipped for localstack).

data "aws_ami" "al2023" {
  count       = var.local ? 0 : 1
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security group for the Nitro Enclave instance.
resource "aws_security_group" "nitro" {
  count = var.local ? 0 : 1

  name_prefix = "${local.prefix}-nitro-"
  description = "Private SG for Nitro Enclave EC2 instance"
  vpc_id      = aws_vpc.main[0].id

  tags = { Name = "${local.prefix}-nitro-sg" }
}

# Allow HTTPS from internet.
resource "aws_security_group_rule" "https_ingress" {
  count = var.local ? 0 : 1

  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nitro[0].id
}

# Self-referencing TCP 443.
resource "aws_security_group_rule" "self_tcp" {
  count = var.local ? 0 : 1

  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nitro[0].id
  security_group_id        = aws_security_group.nitro[0].id
}

# Self-referencing ICMP.
resource "aws_security_group_rule" "self_icmp" {
  count = var.local ? 0 : 1

  type                     = "ingress"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.nitro[0].id
  security_group_id        = aws_security_group.nitro[0].id
}

# All outbound.
resource "aws_security_group_rule" "all_egress" {
  count = var.local ? 0 : 1

  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nitro[0].id
}

# Nitro Enclave EC2 instance.
resource "aws_instance" "nitro" {
  count = var.local ? 0 : 1

  ami                  = data.aws_ami.al2023[0].id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.public[0].id
  iam_instance_profile = aws_iam_instance_profile.instance.name
  vpc_security_group_ids = [aws_security_group.nitro[0].id]

  enclave_options {
    enabled = true
  }

  root_block_device {
    volume_size           = 32
    volume_type           = "gp2"
    encrypted             = true
    delete_on_termination = var.deployment == "dev"
  }

  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region                       = var.region
    dev_mode                     = var.deployment
    app_name                     = var.app_name
    kms_key_id                   = aws_kms_key.encryption.key_id
    eif_s3_url                   = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.enclave_eif.key}"
    enclave_init_s3_url          = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.enclave_init.key}"
    enclave_init_systemd_s3_url  = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.watchdog_systemd.key}"
    imds_systemd_s3_url          = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.imds_systemd.key}"
    gvproxy_systemd_s3_url       = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.gvproxy_systemd.key}"
    mgmt_binary_s3_url           = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.mgmt_binary.key}"
    mgmt_systemd_s3_url          = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.mgmt_systemd.key}"
    gvproxy_binary_s3_url        = "s3://${aws_s3_bucket.assets.id}/${aws_s3_object.gvproxy_binary.key}"
    migration_cooldown           = var.migration_cooldown
    previous_pcr0                = var.previous_pcr0
  })

  tags = {
    Name   = "${local.prefix}-nitro-enclave"
    Region = var.region
  }

  # Wait for instance to pass status checks before proceeding.
  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${self.id} --region ${var.region}"
  }

  # On destroy: stop enclave + schedule KMS key deletion via mgmt server.
  # Must run while the instance is still alive (before EC2 termination).
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      aws ssm send-command \
        --instance-ids ${self.id} \
        --document-name AWS-RunShellScript \
        --parameters '{"commands":["curl -sf -X POST http://localhost:8443/stop || true","curl -sf -X POST http://localhost:8443/schedule-key-deletion || true"]}' \
        --region ${self.tags["Region"]} \
        --output text || true
    EOT
    on_failure = continue
  }
}

# SSM parameters for instance metadata (used by upgrade detection + destroy).
resource "aws_ssm_parameter" "instance_id" {
  count = var.local ? 0 : 1
  name  = "/${var.deployment}/${var.app_name}/InstanceID"
  type  = "String"
  value = aws_instance.nitro[0].id
}

resource "aws_ssm_parameter" "elastic_ip" {
  count = var.local ? 0 : 1
  name  = "/${var.deployment}/${var.app_name}/ElasticIP"
  type  = "String"
  value = aws_eip.instance[0].public_ip
}

# Elastic IP for stable public address across reboots.
resource "aws_eip" "instance" {
  count  = var.local ? 0 : 1
  domain = "vpc"

  tags = { Name = "${local.prefix}-enclave-eip" }
}

resource "aws_eip_association" "instance" {
  count = var.local ? 0 : 1

  allocation_id = aws_eip.instance[0].id
  instance_id   = aws_instance.nitro[0].id
}

# Automatic migration — triggers when the EIF changes (new PCR0).
# On first apply this is a no-op (no running enclave to migrate).
# On subsequent applies with a new EIF, it calls the mgmt server to
# perform a live migration (export keys, swap EIF, restart enclave).
# Automatic migration (production) — triggers when EIF changes.
# Uses SSM to call the mgmt server on the EC2 instance.
resource "null_resource" "enclave_migration" {
  count = var.local ? 0 : 1

  triggers = {
    eif_key       = aws_s3_object.enclave_eif.key
    expected_pcr0 = var.expected_pcr0
  }

  provisioner "local-exec" {
    command = <<-EOT
      INSTANCE_ID="${aws_instance.nitro[0].id}"
      REGION="${var.region}"
      BUCKET="${aws_s3_bucket.assets.id}"
      EIF_KEY="${aws_s3_object.enclave_eif.key}"
      PCR0="${var.expected_pcr0}"
      SECRETS='${jsonencode([for s in var.secrets : s.name])}'

      # Skip on first deploy (no running enclave).
      STATUS=$(aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name AWS-RunShellScript \
        --parameters '{"commands":["curl -sf http://localhost:8443/health || echo NOT_RUNNING"]}' \
        --region "$REGION" \
        --query 'Command.CommandId' --output text 2>/dev/null) || exit 0
      sleep 5
      RESULT=$(aws ssm get-command-invocation \
        --command-id "$STATUS" --instance-id "$INSTANCE_ID" --region "$REGION" \
        --query 'StandardOutputContent' --output text 2>/dev/null) || exit 0
      if echo "$RESULT" | grep -q "NOT_RUNNING"; then
        echo "No running enclave, skipping migration."
        exit 0
      fi

      echo "Triggering migration..."
      MIGRATE_CMD="curl -sf -X POST http://localhost:8443/migrate -H Content-Type:application/json -d '{\"eif_bucket\":\"$BUCKET\",\"eif_key\":\"$EIF_KEY\",\"pcr0\":\"$PCR0\",\"secret_names\":$SECRETS}'"
      aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name AWS-RunShellScript \
        --parameters "{\"commands\":[\"$MIGRATE_CMD\"]}" \
        --region "$REGION" --output text
    EOT
  }

  depends_on = [aws_instance.nitro, aws_s3_object.enclave_eif]
}

# Automatic migration (local mode) — triggers when expected_pcr0 changes.
# Calls the mgmt server directly via HTTP (no EC2/SSM in local mode).
resource "null_resource" "enclave_migration_local" {
  count = var.local && var.expected_pcr0 != "" ? 1 : 0

  triggers = {
    expected_pcr0 = var.expected_pcr0
  }

  provisioner "local-exec" {
    command = <<-EOT
      MGMT_URL="${var.mgmt_url}"
      BUCKET="${aws_s3_bucket.assets.id}"
      PCR0="${var.expected_pcr0}"
      SECRETS='${jsonencode([for s in var.secrets : s.name])}'

      # Skip on first deploy (mgmt server not running yet).
      curl -sf "$${MGMT_URL}/health" >/dev/null 2>&1 || { echo "No mgmt server, skipping migration."; exit 0; }

      echo "Triggering local migration..."
      curl -sf -X POST "$${MGMT_URL}/migrate" \
        -H 'Content-Type: application/json' \
        -d "{\"eif_bucket\":\"$${BUCKET}\",\"eif_key\":\"image.eif\",\"pcr0\":\"$${PCR0}\",\"secret_names\":$${SECRETS}}"
    EOT
  }
}
`

const tofuModuleBackendMain = `# Bootstrap module for the OpenTofu state backend.
# Creates an S3 bucket for state storage and a DynamoDB table for locking.
# This module uses local state (the backend can't store its own state).
#
# Usage:
#   cd modules/backend
#   tofu init
#   tofu apply -var="bucket_name=myapp-tfstate" -var="table_name=myapp-tfstate-lock" -var="region=us-east-1"

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_s3_bucket" "state" {
  bucket = var.bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "lock" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
`

const tofuModuleBackendVariables = `variable "bucket_name" {
  description = "S3 bucket name for OpenTofu state storage."
  type        = string
}

variable "table_name" {
  description = "DynamoDB table name for state locking."
  type        = string
}

variable "region" {
  description = "AWS region."
  type        = string
}
`

const tofuModuleBackendOutputs = `output "bucket_name" {
  description = "S3 bucket name for state storage."
  value       = aws_s3_bucket.state.id
}

output "table_name" {
  description = "DynamoDB table name for state locking."
  value       = aws_dynamodb_table.lock.name
}
`

const tofuMigrateState = `#!/usr/bin/env bash
# Migrate OpenTofu state from the flat layout (resources at root)
# to the module layout (resources under module.enclave).
#
# Run this ONCE after upgrading to the module-based structure.
# Requires: tofu CLI, initialized state backend.
#
# Usage:
#   cd enclave/tofu
#   bash migrate-state.sh

set -euo pipefail

echo "=== OpenTofu State Migration ==="
echo "Moving resources from root to module.enclave"
echo ""

# Helper: move a resource, skip if it doesn't exist in state.
move() {
  local from="$1" to="$2"
  if tofu state show "$from" &>/dev/null; then
    echo "  $from -> $to"
    tofu state mv "$from" "$to"
  else
    echo "  (skip) $from not in state"
  fi
}

echo "--- KMS ---"
move "aws_kms_key.encryption"        "module.enclave.aws_kms_key.encryption"
move "aws_kms_key_policy.encryption"  "module.enclave.aws_kms_key_policy.encryption"

echo ""
echo "--- IAM ---"
move "aws_iam_role.instance"                      "module.enclave.aws_iam_role.instance"
move "aws_iam_instance_profile.instance"           "module.enclave.aws_iam_instance_profile.instance"
move "aws_iam_role_policy_attachment.ssm_core[0]"  "module.enclave.aws_iam_role_policy_attachment.ssm_core[0]"
move "aws_iam_role_policy.enclave"                 "module.enclave.aws_iam_role_policy.enclave"

echo ""
echo "--- S3 ---"
move "aws_s3_bucket.assets"                    "module.enclave.aws_s3_bucket.assets"
move "aws_s3_bucket_public_access_block.assets" "module.enclave.aws_s3_bucket_public_access_block.assets"
move "aws_s3_object.enclave_eif"               "module.enclave.aws_s3_object.enclave_eif"
move "aws_s3_object.enclave_init"              "module.enclave.aws_s3_object.enclave_init"
move "aws_s3_object.watchdog_systemd"          "module.enclave.aws_s3_object.watchdog_systemd"
move "aws_s3_object.imds_systemd"              "module.enclave.aws_s3_object.imds_systemd"
move "aws_s3_object.gvproxy_systemd"           "module.enclave.aws_s3_object.gvproxy_systemd"
move "aws_s3_object.mgmt_binary"               "module.enclave.aws_s3_object.mgmt_binary"
move "aws_s3_object.mgmt_systemd"              "module.enclave.aws_s3_object.mgmt_systemd"
move "aws_s3_bucket.storage"                   "module.enclave.aws_s3_bucket.storage"
move "aws_s3_bucket_public_access_block.storage" "module.enclave.aws_s3_bucket_public_access_block.storage"
move "aws_s3_bucket_policy.storage_ssl[0]"     "module.enclave.aws_s3_bucket_policy.storage_ssl[0]"

echo ""
echo "--- SSM ---"
# Dynamic per-secret parameters — enumerate from state.
for addr in $(tofu state list 2>/dev/null | grep '^aws_ssm_parameter\.'); do
  move "$addr" "module.enclave.$addr"
done

echo ""
echo "--- VPC ---"
move "aws_vpc.main[0]"                          "module.enclave.aws_vpc.main[0]"
move "aws_subnet.public[0]"                     "module.enclave.aws_subnet.public[0]"
move "aws_subnet.private[0]"                    "module.enclave.aws_subnet.private[0]"
move "aws_subnet.private_b[0]"                  "module.enclave.aws_subnet.private_b[0]"
move "aws_internet_gateway.main[0]"             "module.enclave.aws_internet_gateway.main[0]"
move "aws_eip.nat[0]"                           "module.enclave.aws_eip.nat[0]"
move "aws_nat_gateway.main[0]"                  "module.enclave.aws_nat_gateway.main[0]"
move "aws_route_table.public[0]"                "module.enclave.aws_route_table.public[0]"
move "aws_route_table_association.public[0]"    "module.enclave.aws_route_table_association.public[0]"
move "aws_route_table.private[0]"               "module.enclave.aws_route_table.private[0]"
move "aws_route_table_association.private[0]"   "module.enclave.aws_route_table_association.private[0]"
move "aws_route_table_association.private_b[0]" "module.enclave.aws_route_table_association.private_b[0]"
move "aws_vpc_endpoint.kms[0]"                  "module.enclave.aws_vpc_endpoint.kms[0]"
move "aws_vpc_endpoint.ssm[0]"                  "module.enclave.aws_vpc_endpoint.ssm[0]"
move "aws_vpc_endpoint.ecr[0]"                  "module.enclave.aws_vpc_endpoint.ecr[0]"
move "aws_vpc_endpoint.s3[0]"                   "module.enclave.aws_vpc_endpoint.s3[0]"

echo ""
echo "--- EC2 ---"
move "aws_security_group.nitro[0]"              "module.enclave.aws_security_group.nitro[0]"
move "aws_security_group_rule.https_ingress[0]" "module.enclave.aws_security_group_rule.https_ingress[0]"
move "aws_security_group_rule.self_tcp[0]"      "module.enclave.aws_security_group_rule.self_tcp[0]"
move "aws_security_group_rule.self_icmp[0]"     "module.enclave.aws_security_group_rule.self_icmp[0]"
move "aws_security_group_rule.all_egress[0]"    "module.enclave.aws_security_group_rule.all_egress[0]"
move "aws_instance.nitro[0]"                    "module.enclave.aws_instance.nitro[0]"
move "aws_eip.instance[0]"                      "module.enclave.aws_eip.instance[0]"
move "aws_eip_association.instance[0]"          "module.enclave.aws_eip_association.instance[0]"

echo ""
echo "=== Migration complete ==="
echo "Run 'tofu plan' to verify no changes are needed."
`
