output "test_bucket_name" {
  description = "Name of the dedicated security assessment test bucket"
  value       = aws_s3_bucket.security_test.id
}

output "aws_region" {
  description = "AWS region used for testing"
  value       = "us-east-1"
}

output "test_configuration" {
  description = "Expected bucket-level security assessment status"
  value       = "COMPLETE_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK"
}
