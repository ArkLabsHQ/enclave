# KMS encryption key for enclave secrets.
#
# Created via AWS CLI (null_resource) instead of a native tofu resource
# because the enclave locks the key policy to PCR0 at first boot, and the
# mgmt server replaces the key entirely during migration. Tofu cannot
# refresh a locked key (DescribeKey/GetKeyPolicy/GetKeyRotationStatus all
# fail with AccessDenied), so the key must not exist as a tofu resource.
#
# The key ID is stored in SSM and read back via a data source. All other
# resources reference locals.kms_key_id / locals.kms_key_arn.
# Key deletion is handled by the mgmt server's destroy provisioner.

resource "null_resource" "kms_key" {
  # Only runs once per deployment. The mgmt server handles key rotation
  # during migration (creates new keys, updates SSM).
  triggers = {
    deployment = var.deployment
    app_name   = var.app_name
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -e

      # Check if a key already exists in SSM (idempotent).
      EXISTING=$(aws ssm get-parameter \
        --name "/${var.deployment}/${var.app_name}/KMSKeyID" \
        --region ${var.region} --query 'Parameter.Value' --output text 2>/dev/null || echo "UNSET")
      if [ "$EXISTING" != "UNSET" ] && [ -n "$EXISTING" ]; then
        echo "KMS key already exists in SSM: $EXISTING"
        exit 0
      fi

      # Create the key.
      KEY_ID=$(aws kms create-key \
        --description "${local.prefix} enclave encryption key" \
        --region ${var.region} \
        --tags TagKey=AppName,TagValue=${var.app_name} TagKey=Deployment,TagValue=${var.deployment} TagKey=ManagedBy,TagValue=opentofu \
        --query 'KeyMetadata.KeyId' --output text)
      echo "Created KMS key: $KEY_ID"

      # Apply initial key policy.
      POLICY='${jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid       = "AllowRootAccount"
            Effect    = "Allow"
            Principal = { AWS = "arn:aws:iam::${var.account}:root" }
            Action    = "kms:*"
            Resource  = "*"
          },
          {
            Sid       = "AllowInstanceRole"
            Effect    = "Allow"
            Principal = { AWS = aws_iam_role.instance.arn }
            Action = [
              "kms:Encrypt",
              "kms:Decrypt",
              "kms:GenerateDataKey",
              "kms:DescribeKey",
              "kms:PutKeyPolicy",
              "kms:GetKeyPolicy",
            ]
            Resource = "*"
          },
        ]
      })}'

      aws kms put-key-policy --key-id "$KEY_ID" --policy-name default \
        --policy "$POLICY" --region ${var.region}

      # Store in SSM.
      aws ssm put-parameter \
        --name "/${var.deployment}/${var.app_name}/KMSKeyID" \
        --value "$KEY_ID" --type String --overwrite \
        --region ${var.region} --no-cli-pager

      echo "KMS key $KEY_ID stored in SSM"
    EOT
  }
}

# Read the KMS key ID from SSM (written by null_resource.kms_key or mgmt server).
data "aws_ssm_parameter" "kms_key_id_lookup" {
  name       = "/${var.deployment}/${var.app_name}/KMSKeyID"
  depends_on = [null_resource.kms_key]
}

locals {
  kms_key_id  = data.aws_ssm_parameter.kms_key_id_lookup.value
  kms_key_arn = "arn:aws:kms:${var.region}:${var.account}:key/${local.kms_key_id}"
}
