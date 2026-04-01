variable "bucket_name" {
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
