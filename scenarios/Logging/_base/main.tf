data "aws_caller_identity" "current" {}

# KMS.4 — key rotation enabled
resource "aws_kms_key" "cloudtrail" {
  description             = "CIS KMS key for CloudTrail"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Logging"
  }
}

# CloudTrail.6 — S3 bucket access logging enabled
# CloudTrail.7 — S3 bucket not public
resource "aws_s3_bucket" "trail" {
  bucket        = "cis-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Logging"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "trail" {
  bucket        = aws_s3_bucket.trail.id
  target_bucket = aws_s3_bucket.trail.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

# CloudTrail.5 — CloudWatch log group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cis/cloudtrail"
  retention_in_days = 365

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Logging"
  }
}

# IAM role for CloudTrail → CloudWatch Logs delivery
resource "aws_iam_role" "cloudtrail_cw" {
  name = "cis-cloudtrail-cloudwatch-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Logging"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "cis-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# CloudTrail.1 — enabled in all regions (multi-region)
# CloudTrail.2 — log file validation enabled
# CloudTrail.4 — CloudTrail SSE-KMS encryption enabled
# CloudTrail.5 — CloudWatch Logs integration
# CloudTrail.6 — S3 bucket access logging (via aws_s3_bucket_logging above)
# CloudTrail.7 — S3 bucket not publicly accessible (via public access block above)
resource "aws_cloudtrail" "main" {
  name                          = "cis-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn

  depends_on = [aws_s3_bucket_policy.trail]

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Logging"
  }
}

# Config.1 — AWS Config enabled with all resource types
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
    Scenario   = "compliant"
    ResearchID = "Logging"
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "cis-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "cis-config-delivery"
  s3_bucket_name = aws_s3_bucket.trail.id

  depends_on = [aws_config_configuration_recorder.main]
}
