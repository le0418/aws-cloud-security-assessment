data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "security_test" {
  bucket_prefix = "aws-security-assessment-test-"

  force_destroy = false

  tags = {
    Project     = "aws-cloud-security-assessment"
    Environment = "dev"
    Purpose     = "Controlled security configuration testing"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "security_test" {
  bucket = aws_s3_bucket.security_test.id

  # Secure baseline: all four bucket-level protections enabled.
  # Account-level protections are managed separately.
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_test" {
  bucket = aws_s3_bucket.security_test.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
