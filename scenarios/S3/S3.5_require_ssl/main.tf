# =============================================================
# CIS AWS Foundations Benchmark v1.4.0
# Control: S3.5
# Description: S3 general purpose buckets should require
#              requests to use SSL
# Scenario: VULNERABLE — bucket policy missing SSL enforcement
# Terraform resource: aws_s3_bucket, aws_s3_bucket_policy
# Expected findings:
#   Checkov: CKV_AWS_70
#   Trivy:   AVD-AWS-0088
#   KICS:    4bc4dd4c-7d8d-405e-a0fb-57fa4c31b4d9
#   Prowler: s3_bucket_secure_transport_policy
# Cost risk: none
# =============================================================



resource "aws_s3_bucket" "s3_5_bucket" {
  bucket = "research-s3-5-ssl-enforcement-al2"

  tags = {
    ResearchID  = "S3.5"
    Standard    = "CIS-AWS-1.4.0"
    Environment = "thesis-lab"
    Scenario    = "vulnerable"
    Tool        = "terraform"
  }
}

# VULNERABLE: no bucket policy enforcing ssl (aws:SecureTransport)
# Compliant version would require policy with
# Condition: {"Bool": {"aws:SecureTransport": "false"}} Effect: Deny