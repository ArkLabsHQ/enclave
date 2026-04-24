locals {
  # When local paths are set, use them directly. Otherwise download from GitHub Release.
  use_local      = var.eif_path != ""
  artifacts_dir  = "${path.module}/.artifacts"
  release_base   = "https://github.com/${var.github_owner}/${var.github_repo}/releases/download/${var.release_tag}"

  eif_source        = local.use_local ? var.eif_path : "${local.artifacts_dir}/image.eif"
  supervisor_source = local.use_local ? var.supervisor_binary_path : "${local.artifacts_dir}/supervisor"
}

# Download build artifacts from GitHub Release (skipped when local paths are set).
resource "null_resource" "download_artifacts" {
  count = local.use_local ? 0 : 1

  triggers = {
    release_tag = var.release_tag
  }

  provisioner "local-exec" {
    command = <<-EOT
      AUTH=""
      [ -n "$GITHUB_TOKEN" ] && AUTH="-H \"Authorization: Bearer $GITHUB_TOKEN\""
      mkdir -p ${local.artifacts_dir}
      eval curl -sfL $AUTH -o ${local.artifacts_dir}/image.eif ${local.release_base}/image.eif
      eval curl -sfL $AUTH -o ${local.artifacts_dir}/supervisor ${local.release_base}/supervisor
    EOT
    environment = {
      GITHUB_TOKEN = var.github_token
    }
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

resource "aws_s3_object" "supervisor_binary" {
  depends_on = [null_resource.download_artifacts]
  bucket     = aws_s3_bucket.assets.id
  key        = "supervisor"
  source     = local.supervisor_source
  etag       = local.use_local ? filemd5(local.supervisor_source) : null
}

# Staging copy used for in-place supervisor migration. Each tofu apply overwrites
# this object with the freshly-built binary; the migration null_resource
# points the running supervisor at this key. On migration success the
# promote_supervisor_binary null_resource copies it onto the canonical key above,
# so instance reboots come up on the new version. If migration fails the
# canonical key stays on the last-known-good binary.
#
# Recovery: if a newly deployed supervisor binary crash-loops under systemd,
# SSM into the host and run
#   aws s3 cp s3://<assets>/supervisor /home/ec2-user/app/supervisor
#   systemctl restart supervisor
# to roll back to the canonical (last-known-good) binary.
resource "aws_s3_object" "supervisor_binary_staging" {
  depends_on = [null_resource.download_artifacts]
  bucket     = aws_s3_bucket.assets.id
  key        = "supervisor-staging"
  source     = local.supervisor_source
  etag       = local.use_local ? filemd5(local.supervisor_source) : null
}

# The enclave-supervisor.service systemd unit is inlined in user_data.sh.tftpl
# via a heredoc — no separate S3 object. Keeps deployment concerns colocated
# with the tofu module that owns them.

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
