output "vpc_id" { value = aws_vpc.lab.id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "workload_security_group_id" { value = aws_security_group.workload.id }
output "audit_function_name" { value = aws_lambda_function.audit.function_name }
output "findings_topic_arn" { value = aws_sns_topic.findings.arn }
output "failure_queue_url" { value = aws_sqs_queue.failures.url }
output "flow_log_group" { value = aws_cloudwatch_log_group.flow.name }
