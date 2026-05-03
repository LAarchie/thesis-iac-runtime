data "aws_caller_identity" "current" {}

# S3.8 — Brak bloku public access (resource usunięty)
resource "aws_s3_bucket" "cis" {
  bucket        = "cis-s3-test-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "S3.8"
  }
}

# S3.5 — Wymuszanie HTTPS (deny HTTP)
resource "aws_s3_bucket_policy" "cis" {
  bucket = aws_s3_bucket.cis.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyHTTP"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.cis.arn,
        "${aws_s3_bucket.cis.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

# S3.20 — Versioning włączone (MFA Delete wymaga root+MFA,
# nie można ustawić przez standardowy provider)
resource "aws_s3_bucket_versioning" "cis" {
  bucket = aws_s3_bucket.cis.id
  versioning_configuration {
    status = "Enabled"
  }
}
