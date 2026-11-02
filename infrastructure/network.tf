resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.project_name }
}
resource "aws_subnet" "private" {
  count                   = 2
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.project_name}-private-${count.index + 1}" }
}
resource "aws_default_security_group" "locked" {
  vpc_id = aws_vpc.lab.id
  # No ingress or egress rules: deny all by default.
}
resource "aws_security_group" "workload" {
  name        = "${var.project_name}-workload"
  description = "Lab workload security group; no access by default"
  vpc_id      = aws_vpc.lab.id
}
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/${var.project_name}"
  retention_in_days = 30
}
resource "aws_iam_role" "flow" {
  name = "${var.project_name}-flow"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = {
      StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*" }
    }
  }] })
}
resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect   = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
    Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
  }] })
}
resource "aws_flow_log" "lab" {
  iam_role_arn    = aws_iam_role.flow.arn
  log_destination = aws_cloudwatch_log_group.flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.lab.id
  depends_on      = [aws_iam_role_policy.flow]
}
