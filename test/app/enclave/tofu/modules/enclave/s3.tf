locals {
  # When local paths are set, use them directly. Otherwise download from GitHub Release.
  use_local      = var.eif_path != ""
  artifacts_dir  = "${path.module}/.artifacts"
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
      AUTH=""
      [ -n "$GITHUB_TOKEN" ] && AUTH="-H \"Authorization: Bearer $GITHUB_TOKEN\""
      mkdir -p ${local.artifacts_dir}
      eval curl -sfL $AUTH -o ${local.artifacts_dir}/image.eif ${local.release_base}/image.eif
      eval curl -sfL $AUTH -o ${local.artifacts_dir}/enclave-mgmt ${local.release_base}/enclave-mgmt
      eval curl -sfL $AUTH -o ${local.artifacts_dir}/gvproxy ${local.release_base}/gvproxy
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

resource "aws_s3_object" "gvproxy_start_script" {
  bucket = aws_s3_bucket.assets.id
  key    = "gvproxy-start.sh"
  source = var.gvproxy_start_script_path
  etag   = filemd5(var.gvproxy_start_script_path)
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
