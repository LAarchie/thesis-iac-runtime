resource "aws_iam_policy" "cis_test" {
  name = "cis-test-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "*"
    }]
  })

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "IAM"
  }
}

resource "aws_iam_account_password_policy" "cis" {
  minimum_password_length        = 14
  password_reuse_prevention      = 24
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  max_password_age               = 90
  allow_users_to_change_password = true
}

resource "aws_iam_role" "support" {
  name = "cis-support-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "support.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "IAM"
  }
}

resource "aws_iam_role_policy_attachment" "support" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

resource "aws_iam_user" "cis_test" {
  name = "cis-test-user"

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "IAM"
  }
}
