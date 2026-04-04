# Root module outputs — re-exported from sub-modules.

output "ec2_role_arn" {
  description = "EC2 instance role ARN."
  value       = module.enclave.ec2_role_arn
}

output "kms_key_id" {
  description = "KMS encryption key ID."
  value       = module.enclave.kms_key_id
  sensitive   = true
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

