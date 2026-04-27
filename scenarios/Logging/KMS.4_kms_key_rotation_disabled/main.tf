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
