output "bucket_name" {
  description = "S3 bucket name for state storage."
  value       = aws_s3_bucket.state.id
}

output "table_name" {
  description = "DynamoDB table name for state locking."
  value       = aws_dynamodb_table.lock.name
}
