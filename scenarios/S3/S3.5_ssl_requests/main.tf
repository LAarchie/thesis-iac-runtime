data "aws_caller_identity" "current" {}

# S3.1 i S3.8 — Block public access na poziomie bucketu
resource "aws_s3_bucket" "cis" {
  bucket        = "cis-s3-test-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "S3.5"
  }
}

resource "aws_s3_bucket_public_access_block" "cis" {
  bucket                  = aws_s3_bucket.cis.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3.5 — Narzędzia szukają Effect = Deny, SecureTransport = false - w tym przypadku jest przeciwieństwo i wyrzuci błąd dla tej reguły
resource "aws_s3_bucket_policy" "cis" {
  bucket = aws_s3_bucket.cis.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "NOT-RECOMMENDED-FOR__AWSCONFIG-Rule_s3-bucket-ssl-requests-only"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource = [
        "${aws_s3_bucket.cis.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "true" }
      }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.cis]
}

# S3.20 — Versioning włączone (MFA Delete wymaga root+MFA,
# nie można ustawić przez standardowy provider)
resource "aws_s3_bucket_versioning" "cis" {
  bucket = aws_s3_bucket.cis.id
  versioning_configuration {
    status = "Enabled"
  }
}
