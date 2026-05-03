data "aws_caller_identity" "current" {}

# S3.1 i S3.8 — Block public access na poziomie bucketu
resource "aws_s3_bucket" "cis" {
  bucket        = "cis-s3-test-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "S3.20"
  }
}

resource "aws_s3_bucket_public_access_block" "cis" {
  bucket                  = aws_s3_bucket.cis.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
  depends_on = [aws_s3_bucket_public_access_block.cis]
}

# S3.20 — Blok versioning usunięty (MFA Delete nie skonfigurowany)
