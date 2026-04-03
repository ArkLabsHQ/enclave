output "ec2_role_arn" {
  description = "EC2 instance role ARN."
  value       = aws_iam_role.instance.arn
}

output "kms_key_id" {
  description = "KMS encryption key ID."
  value       = local.kms_key_id
  sensitive   = true
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
