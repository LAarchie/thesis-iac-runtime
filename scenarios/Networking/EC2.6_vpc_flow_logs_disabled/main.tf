data "aws_caller_identity" "current" {}

# EC2.6 — VULNERABLE: VPC bez Flow Logs
resource "aws_vpc" "cis" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "EC2.6"
  }
}

# Brak aws_flow_log — to jest celowa podatność
# aws_flow_log jest zdefiniowany w _base ale tutaj go nie ma
