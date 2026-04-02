# SSM parameters for enclave secrets and migration state.

locals {
  secrets_map = { for s in var.secrets : s.name => s }
}

# Per-secret ciphertext parameters.
resource "aws_ssm_parameter" "secret_ciphertext" {
  for_each = local.secrets_map

  name      = "/${var.deployment}/${var.app_name}/${each.key}/Ciphertext"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

# Per-secret migration ciphertext parameters.
resource "aws_ssm_parameter" "secret_migration" {
  for_each = local.secrets_map

  name      = "/${var.deployment}/${var.app_name}/Migration/${each.key}/Ciphertext"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

# Shared migration parameters (one per deployment, not per secret).

resource "aws_ssm_parameter" "migration_kms_key_id" {
  name      = "/${var.deployment}/${var.app_name}/MigrationKMSKeyID"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "migration_previous_pcr0" {
  name      = "/${var.deployment}/${var.app_name}/MigrationPreviousPCR0"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "migration_previous_pcr0_attestation" {
  name      = "/${var.deployment}/${var.app_name}/MigrationPreviousPCR0Attestation"
  type      = "String"
  tier      = "Advanced"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "migration_old_kms_key_id" {
  name      = "/${var.deployment}/${var.app_name}/MigrationOldKMSKeyID"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

# KMS key ID (auto-populated with the actual key ID).
resource "aws_ssm_parameter" "kms_key_id" {
  name      = "/${var.deployment}/${var.app_name}/KMSKeyID"
  type      = "String"
  value     = aws_kms_key.encryption.key_id
  overwrite = true
}

# Storage bucket name.
resource "aws_ssm_parameter" "storage_bucket_name" {
  name      = "/${var.deployment}/${var.app_name}/StorageBucketName"
  type      = "String"
  value     = aws_s3_bucket.storage.id
  overwrite = true
}

# Storage data encryption key (DEK).
resource "aws_ssm_parameter" "storage_dek" {
  name      = "/${var.deployment}/${var.app_name}/StorageDEK/Ciphertext"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}

# Migration storage DEK.
resource "aws_ssm_parameter" "migration_storage_dek" {
  name      = "/${var.deployment}/${var.app_name}/Migration/StorageDEK/Ciphertext"
  type      = "String"
  value     = "UNSET"
  overwrite = true

  lifecycle {
    ignore_changes = [value]
  }
}
