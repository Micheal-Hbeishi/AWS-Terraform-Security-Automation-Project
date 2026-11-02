resource "aws_sns_topic" "findings" {
  name              = "${var.project_name}-findings"
  kms_master_key_id = aws_kms_key.notifications.arn
}
resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.notification_email
}
resource "aws_sqs_queue" "failures" {
  name                      = "${var.project_name}-failures"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600
}
resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/lambda/${var.project_name}-audit"
  retention_in_days = 30
}
resource "aws_iam_role" "audit" {
  name = "${var.project_name}-audit"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_iam_role_policy" "audit" {
  role = aws_iam_role.audit.id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([
    { Effect = "Allow", Action = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules"], Resource = "*" },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.audit.arn}:*" },
    { Effect = "Allow", Action = ["sns:Publish"], Resource = aws_sns_topic.findings.arn },
    { Effect = "Allow", Action = ["kms:GenerateDataKey*", "kms:Decrypt"], Resource = aws_kms_key.notifications.arn, Condition = { StringEquals = { "kms:ViaService" = "sns.${var.aws_region}.amazonaws.com" } } },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.failures.arn }
    ], var.enable_remediation ? [{
      Effect    = "Allow", Action = ["ec2:RevokeSecurityGroupIngress"],
      Resource  = "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:security-group/*",
      Condition = { ArnEquals = { "ec2:Vpc" = aws_vpc.lab.arn } }
  }] : []) })
}
data "archive_file" "audit" {
  type        = "zip"
  source_file = "${path.module}/../automation/security_audit.py"
  output_path = "${path.module}/audit.zip"
}
resource "aws_lambda_function" "audit" {
  function_name                  = "${var.project_name}-audit"
  role                           = aws_iam_role.audit.arn
  runtime                        = "python3.12"
  handler                        = "security_audit.handler"
  filename                       = data.archive_file.audit.output_path
  source_code_hash               = data.archive_file.audit.output_base64sha256
  timeout                        = 120
  memory_size                    = 128
  reserved_concurrent_executions = 1
  environment {
    variables = {
      VPC_ID          = aws_vpc.lab.id
      TOPIC_ARN       = aws_sns_topic.findings.arn
      REMEDIATE       = tostring(var.enable_remediation)
      PROTECTED_PORTS = join(",", var.protected_ports)
    }
  }
  dead_letter_config { target_arn = aws_sqs_queue.failures.arn }
  depends_on = [aws_iam_role_policy.audit, aws_cloudwatch_log_group.audit]
}
resource "aws_cloudwatch_event_rule" "audit" {
  name                = "${var.project_name}-schedule"
  schedule_expression = "rate(5 minutes)"
}
resource "aws_cloudwatch_event_target" "audit" {
  rule = aws_cloudwatch_event_rule.audit.name
  arn  = aws_lambda_function.audit.arn
}
resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowScheduledAudit"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.audit.arn
}
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.project_name}-audit-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.audit.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.findings.arn]
}

resource "aws_kms_key" "notifications" {
  description             = "Encrypt security notifications"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "AccountAdministration", Effect = "Allow", Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }, Action = "kms:*", Resource = "*" },
    { Sid = "CloudWatchAlarmEncryption", Effect = "Allow", Principal = { Service = "cloudwatch.amazonaws.com" }, Action = ["kms:Decrypt", "kms:GenerateDataKey*"], Resource = "*", Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }, ArnLike = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${var.project_name}-*" } } }
  ] })
}
resource "aws_sns_topic_policy" "findings" {
  arn = aws_sns_topic.findings.arn
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid = "AccountAccess", Effect = "Allow", Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }, Action = "sns:*", Resource = aws_sns_topic.findings.arn },
    { Sid = "CloudWatchPublish", Effect = "Allow", Principal = { Service = "cloudwatch.amazonaws.com" }, Action = "sns:Publish", Resource = aws_sns_topic.findings.arn, Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }, ArnLike = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${var.project_name}-*" } } }
  ] })
}
