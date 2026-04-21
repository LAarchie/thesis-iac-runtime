# =============================================================
# CIS AWS Foundations Benchmark v1.4.0
# Control: S3.1
# Description: S3 general purpose buckets should have block
#              public access settings enabled
# Scenario: VULNERABLE — all block public access flags disabled
# Terraform resource: aws_s3_bucket_public_access_block
# Expected findings:
#   Checkov: CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56
#   Trivy:   AVD-AWS-0086, AVD-AWS-0087
#   KICS:    1a4bc881-9f69-4d44-8c9a-d37d08f54c55
#   Prowler: s3_bucket_level_public_access_block
# Cost risk: none
# =============================================================

resource "aws_s3_bucket" "s3_1_bucket" {
  bucket = "research-s3-1-public-access-block-al2"

  tags = {
    ResearchID  = "S3.1"
    Standard    = "CIS-AWS-1.4.0"
    Environment = "thesis-lab"
    Scenario    = "vulnerable"
    Tool        = "terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "s3_1_public_access" {
  bucket = aws_s3_bucket.s3_1_bucket.id

  # VULNERABLE: all flags disabled — violates S3.1
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}