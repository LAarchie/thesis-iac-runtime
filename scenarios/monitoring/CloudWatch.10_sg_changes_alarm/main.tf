# 1. Bucket S3 for CloudTrail (required by aws_cloudtrail)
resource "aws_s3_bucket" "trail" {
  bucket        = "cis-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Standard   = "CIS-AWS-1.4.0"
    Scenario   = "compliant"
    ResearchID = "Monitoring"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

# 2.  IAM Role for CloudTrail → CloudWatch
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
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "cis-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cis.arn}:*"
    }]
  })
}

# 3. Data source — required for account_id in the bucket names
data "aws_caller_identity" "current" {}




resource "aws_cloudwatch_log_group" "cis" {
  name              = "/cis/cloudtrail"
  retention_in_days = 90
}

resource "aws_sns_topic" "cis_alerts" {
  name = "cis-alerts"
}

resource "aws_cloudtrail" "main" {
  name                          = "cis-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cis.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn
}

# CloudWatch.1 - root usage

resource "aws_cloudwatch_log_metric_filter" "cw1_root" {
  name           = "cis-cw1-root-usage"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootUsageCount"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw1_root" {
  alarm_name          = "cis-cw1-root-usage"
  metric_name         = "RootUsageCount"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.4 IAM Policy changes

resource "aws_cloudwatch_log_metric_filter" "cw4_iam" {
  name           = "cis-cw4-iam-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=SetDefaultPolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }"

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw4_iam" {
  alarm_name          = "cis-cw4-iam-changes"
  metric_name         = "IAMPolicyChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

#CloudWatch.5 - CloudTrail Configuration Change

resource "aws_cloudwatch_log_metric_filter" "cw5_cloudtrail_change" {
  name           = "cis-cw5-ct-config-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"

  metric_transformation {
    name      = "CloudTrailConfigurationChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw5_cloudtrail_change" {
  alarm_name          = "cis-cw5-ct-config-changes"
  metric_name         = "CloudTrailConfigurationChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.6 - Console Authentication Failures

resource "aws_cloudwatch_log_metric_filter" "cw6_console_auth_failures" {
  name           = "cis-cw6-console-auth-failures"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"

  metric_transformation {
    name      = "ConsoleAuthFailures"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw6_console_auth_failures" {
  alarm_name          = "cis-cw6-console-auth-failures"
  metric_name         = "ConsoleAuthFailures"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.7 - Disabling or Scheduled Deletion of Customer Managed Keys

resource "aws_cloudwatch_log_metric_filter" "cw7_cmk_disable_delete" {
  name           = "cis-cw7-cmk-disable-delete"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"

  metric_transformation {
    name      = "CMKDisableOrDelete"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw7_cmk_disable_delete" {
  alarm_name          = "cis-cw7-cmk-disable-delete"
  metric_name         = "CMKDisableOrDelete"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.8 - S3 Bucket Policy Changes

resource "aws_cloudwatch_log_metric_filter" "cw8_s3_policy_changes" {
  name           = "cis-cw8-s3-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw8_s3_policy_changes" {
  alarm_name          = "cis-cw8-s3-policy-changes"
  metric_name         = "S3BucketPolicyChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.9 - AWS Config Configuration Changes

resource "aws_cloudwatch_log_metric_filter" "cw9_config_changes" {
  name           = "cis-cw9-config-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"

  metric_transformation {
    name      = "AWSConfigChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw9_config_changes" {
  alarm_name          = "cis-cw9-config-changes"
  metric_name         = "AWSConfigChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.11 - Network Access Control List (NACL) Changes

resource "aws_cloudwatch_log_metric_filter" "cw11_nacl_changes" {
  name           = "cis-cw11-nacl-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"

  metric_transformation {
    name      = "NACLChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw11_nacl_changes" {
  alarm_name          = "cis-cw11-nacl-changes"
  metric_name         = "NACLChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.12 - Network Gateway Changes

resource "aws_cloudwatch_log_metric_filter" "cw12_gateway_changes" {
  name           = "cis-cw12-gateway-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"

  metric_transformation {
    name      = "NetworkGatewayChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw12_gateway_changes" {
  alarm_name          = "cis-cw12-gateway-changes"
  metric_name         = "NetworkGatewayChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.13 - Route Table Changes

resource "aws_cloudwatch_log_metric_filter" "cw13_route_table_changes" {
  name           = "cis-cw13-route-table-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw13_route_table_changes" {
  alarm_name          = "cis-cw13-route-table-changes"
  metric_name         = "RouteTableChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}

# CloudWatch.14 - VPC Changes

resource "aws_cloudwatch_log_metric_filter" "cw14_vpc_changes" {
  name           = "cis-cw14-vpc-changes"
  log_group_name = aws_cloudwatch_log_group.cis.name
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"

  metric_transformation {
    name      = "VPCChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cw14_vpc_changes" {
  alarm_name          = "cis-cw14-vpc-changes"
  metric_name         = "VPCChanges"
  namespace           = "CISBenchmark"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.cis_alerts.arn]
}
