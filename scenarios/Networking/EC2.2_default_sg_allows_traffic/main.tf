# VPC potrzebne do aws_default_security_group
resource "aws_vpc" "cis" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "EC2.2"
  }
}

# EC2.2 — VULNERABLE: default security group z regułami ingress i egress
resource "aws_default_security_group" "cis" {
  vpc_id = aws_vpc.cis.id

  # Celowa podatność — reguły pozwalające na ruch
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "EC2.2"
  }
}
