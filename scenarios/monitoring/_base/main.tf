resource "aws_cloudwatch_log_group" "cis" {
    name = "/cis/cloudtrail"
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