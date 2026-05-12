data "aws_vpc" "default" {
  default = true
}

# EC2.2 — VULNERABLE: default security group allows all traffic (Prowler)
resource "aws_default_security_group" "cis" {
  vpc_id = data.aws_vpc.default.id
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

# EC2.2 — VPC for Checkov shift-left scanning
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "EC2.2"
  }
}

# EC2.2 — VULNERABLE: default security group allows all traffic (Checkov CKV2_AWS_12)
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id
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

# EC2.6 — VPC flow logs enabled
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/cis/vpc-flow-logs"
  retention_in_days = 90

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Networking"
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "cis-vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Networking"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "cis-vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Networking"
  }
}

# EC2.7 — EBS encryption by default enabled
resource "aws_ebs_encryption_by_default" "main" {
  enabled = true
}

# EC2.21 — NACL denies unrestricted SSH and RDP from 0.0.0.0/0
resource "aws_network_acl" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Networking"
  }
}

resource "aws_network_acl_rule" "deny_ssh" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "deny_rdp" {
  network_acl_id = aws_network_acl.main.id
  rule_number    = 110
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}
