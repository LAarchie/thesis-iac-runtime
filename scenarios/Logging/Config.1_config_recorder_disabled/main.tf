resource "aws_iam_role" "config" {
  name = "cis-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "vulnerable"
    ResearchID = "Config.1"
  }
}

resource "aws_config_configuration_recorder" "cis" {
  name     = "cis-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = false
  }
}

resource "aws_config_delivery_channel" "cis" {
  name           = "cis-config-delivery-channel"
  s3_bucket_name = "cis-config-logs-bucket"

  depends_on = [aws_config_configuration_recorder.cis]
}
