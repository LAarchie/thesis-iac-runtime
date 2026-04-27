resource "aws_vpc" "cis" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "EC2.21"
  }
}

resource "aws_network_acl" "cis" {
  vpc_id = aws_vpc.cis.id

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "EC2.21"
  }
}

resource "aws_network_acl_rule" "allow_ssh" {
  network_acl_id = aws_network_acl.cis.id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}
