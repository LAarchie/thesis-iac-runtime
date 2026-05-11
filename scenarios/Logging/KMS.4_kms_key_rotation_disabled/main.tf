data "aws_caller_identity" "current" {}

resource "aws_kms_key" "cis" {
  description             = "CIS test KMS key - rotation disabled"
  deletion_window_in_days = 7
  enable_key_rotation     = false

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "KMS.4"
  }
}

resource "aws_kms_key_policy" "cis" {
  key_id = aws_kms_key.cis.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })
}
