terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# VPC for secure Lambda execution
resource "aws_vpc" "patch_automation_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "PatchAutomationVPC"
    Environment = var.environment
  }
}

# Private subnets for Lambda
resource "aws_subnet" "lambda_subnet" {
  count             = 2
  vpc_id            = aws_vpc.patch_automation_vpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name        = "PatchAutomationLambdaSubnet-${count.index + 1}"
    Environment = var.environment
    Type        = "Private"
  }
}

# Internet Gateway for VPC
resource "aws_internet_gateway" "patch_automation_igw" {
  vpc_id = aws_vpc.patch_automation_vpc.id
  
  tags = {
    Name        = "PatchAutomationIGW"
    Environment = var.environment
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  depends_on = [aws_internet_gateway.patch_automation_igw]
  
  tags = {
    Name        = "PatchAutomationNATEIP"
    Environment = var.environment
  }
}

# Public subnet for NAT Gateway
resource "aws_subnet" "nat_subnet" {
  vpc_id                  = aws_vpc.patch_automation_vpc.id
  cidr_block              = "10.0.10.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  
  tags = {
    Name        = "PatchAutomationNATSubnet"
    Environment = var.environment
    Type        = "Public"
  }
}

# NAT Gateway for Lambda internet access
resource "aws_nat_gateway" "patch_automation_nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.nat_subnet.id
  depends_on    = [aws_internet_gateway.patch_automation_igw]
  
  tags = {
    Name        = "PatchAutomationNAT"
    Environment = var.environment
  }
}

# Route table for public subnet
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.patch_automation_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.patch_automation_igw.id
  }
  
  tags = {
    Name        = "PatchAutomationPublicRT"
    Environment = var.environment
  }
}

# Route table for private subnets
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.patch_automation_vpc.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.patch_automation_nat.id
  }
  
  tags = {
    Name        = "PatchAutomationPrivateRT"
    Environment = var.environment
  }
}

# Associate route tables
resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.nat_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "private_rta" {
  count          = 2
  subnet_id      = aws_subnet.lambda_subnet[count.index].id
  route_table_id = aws_route_table.private_rt.id
}

# Security Group for Lambda
resource "aws_security_group" "lambda_sg" {
  name_prefix = "patch-automation-lambda-"
  vpc_id      = aws_vpc.patch_automation_vpc.id
  
  # Outbound rules for AWS services
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to AWS services"
  }
  
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for package updates"
  }
  
  tags = {
    Name        = "PatchAutomationLambdaSG"
    Environment = var.environment
  }
}

# VPC Endpoints for AWS services (cost-effective and secure)
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id          = aws_vpc.patch_automation_vpc.id
  service_name    = "com.amazonaws.${var.aws_region}.dynamodb"
  route_table_ids = [aws_route_table.private_rt.id]
  
  tags = {
    Name        = "PatchAutomationDynamoDBEndpoint"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.patch_automation_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.lambda_subnet[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  tags = {
    Name        = "PatchAutomationSSMEndpoint"
    Environment = var.environment
  }
}

resource "aws_vpc_endpoint" "sns" {
  vpc_id              = aws_vpc.patch_automation_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.sns"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.lambda_subnet[*].id
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  
  tags = {
    Name        = "PatchAutomationSNSEndpoint"
    Environment = var.environment
  }
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoint_sg" {
  name_prefix = "patch-automation-vpc-endpoint-"
  vpc_id      = aws_vpc.patch_automation_vpc.id
  
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda_sg.id]
    description     = "HTTPS from Lambda"
  }
  
  tags = {
    Name        = "PatchAutomationVPCEndpointSG"
    Environment = var.environment
  }
}

# DynamoDB table for state management
resource "aws_dynamodb_table" "patch_execution_state" {
  name           = "PatchExecutionState"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "instance_id"
  
  attribute {
    name = "instance_id"
    type = "S"
  }
  
  ttl {
    attribute_name = "expiration_time"
    enabled        = true
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  # Enable encryption
  server_side_encryption {
    enabled = true
  }
  
  tags = {
    Name        = "PatchExecutionState"
    Environment = var.environment
  }
}

# SNS Topic for notifications with encryption
resource "aws_sns_topic" "patch_notifications" {
  name              = "patch-automation-notifications"
  kms_master_key_id = aws_kms_key.patch_automation_key.id
  
  tags = {
    Name        = "PatchAutomationNotifications"
    Environment = var.environment
  }
}

# KMS Key for encryption
resource "aws_kms_key" "patch_automation_key" {
  description             = "KMS key for patch automation encryption"
  deletion_window_in_days = 7
  
  tags = {
    Name        = "PatchAutomationKey"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "patch_automation_key_alias" {
  name          = "alias/patch-automation"
  target_key_id = aws_kms_key.patch_automation_key.key_id
}

resource "aws_sns_topic_subscription" "patch_notifications_email" {
  topic_arn = aws_sns_topic.patch_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_execution_role" {
  name               = "PatchDeduplicationLambdaRole"
  assume_role_policy = file("${path.module}/policies/lambda-assume-role.json")
  
  tags = {
    Name        = "PatchDeduplicationLambdaRole"
    Environment = var.environment
  }
}

# Enhanced Lambda policy with VPC permissions
resource "aws_iam_role_policy" "lambda_execution_policy" {
  name   = "PatchDeduplicationLambdaPolicy"
  role   = aws_iam_role.lambda_execution_role.id
  policy = file("${path.module}/policies/lambda-execution-policy.json")
}

# VPC execution policy for Lambda
resource "aws_iam_role_policy_attachment" "lambda_vpc_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# IAM Role for SSM Automation
resource "aws_iam_role" "automation_execution_role" {
  name               = "ImprovedAutomationRole"
  assume_role_policy = file("${path.module}/policies/automation-assume-role.json")
  
  tags = {
    Name        = "ImprovedAutomationRole"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "automation_ssm_policy" {
  role       = aws_iam_role.automation_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSSMAutomationRole"
}

resource "aws_iam_role_policy" "automation_additional_policy" {
  name   = "AutomationAdditionalPolicy"
  role   = aws_iam_role.automation_execution_role.id
  policy = file("${path.module}/policies/automation-execution-policy.json")
}

# Lambda function package
data "archive_file" "lambda_package" {
  type        = "zip"
  source_file = "${path.module}/../lambda/patch_deduplication.py"
  output_path = "${path.module}/lambda_package.zip"
}

# Enhanced Lambda function with VPC configuration
resource "aws_lambda_function" "patch_deduplication" {
  filename         = data.archive_file.lambda_package.output_path
  function_name    = "patch-deduplication-function"
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "patch_deduplication.lambda_handler"
  source_code_hash = data.archive_file.lambda_package.output_base64sha256
  runtime         = "python3.9"
  timeout         = 300
  memory_size     = 512
  
  # VPC Configuration for security
  vpc_config {
    subnet_ids         = aws_subnet.lambda_subnet[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  environment {
    variables = {
      STATE_TABLE_NAME         = aws_dynamodb_table.patch_execution_state.name
      SNS_TOPIC_ARN           = aws_sns_topic.patch_notifications.arn
      AUTOMATION_DOCUMENT_NAME = aws_ssm_document.improved_patch_automation.name
      AUTOMATION_ROLE_ARN     = aws_iam_role.automation_execution_role.arn
      MAINTENANCE_WINDOW_START = "18"  # 6 PM (for testing - outside current time)
      MAINTENANCE_WINDOW_END   = "22"  # 10 PM
    }
  }
  
  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }
  
  tags = {
    Name        = "PatchDeduplicationFunction"
    Environment = var.environment
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.lambda_vpc_execution,
    aws_cloudwatch_log_group.lambda_logs,
  ]
}

# Maintenance Scheduler Lambda package
data "archive_file" "maintenance_scheduler_package" {
  type        = "zip"
  source_file = "${path.module}/../lambda/maintenance_scheduler.py"
  output_path = "${path.module}/maintenance_scheduler_package.zip"
}

# Maintenance Scheduler Lambda function
resource "aws_lambda_function" "maintenance_scheduler" {
  filename         = data.archive_file.maintenance_scheduler_package.output_path
  function_name    = "patch-maintenance-scheduler"
  role            = aws_iam_role.maintenance_scheduler_role.arn
  handler         = "maintenance_scheduler.lambda_handler"
  source_code_hash = data.archive_file.maintenance_scheduler_package.output_base64sha256
  runtime         = "python3.9"
  timeout         = 300
  memory_size     = 256
  
  # VPC Configuration for security (same as main Lambda)
  vpc_config {
    subnet_ids         = aws_subnet.lambda_subnet[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }
  
  environment {
    variables = {
      STATE_TABLE_NAME               = aws_dynamodb_table.patch_execution_state.name
      MAINTENANCE_WINDOW_START       = "18"  # 6 PM UTC (for testing - same as main Lambda)
      MAINTENANCE_WINDOW_END         = "22"  # 10 PM UTC (for testing - same as main Lambda)
      DEDUPLICATION_FUNCTION_NAME    = aws_lambda_function.patch_deduplication.function_name
    }
  }
  
  tags = {
    Name        = "PatchMaintenanceScheduler"
    Environment = var.environment
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.maintenance_scheduler_vpc_execution,
    aws_cloudwatch_log_group.maintenance_scheduler_logs,
  ]
}

# IAM Role for Maintenance Scheduler Lambda
resource "aws_iam_role" "maintenance_scheduler_role" {
  name               = "PatchMaintenanceSchedulerRole"
  assume_role_policy = file("${path.module}/policies/lambda-assume-role.json")
  
  tags = {
    Name        = "PatchMaintenanceSchedulerRole"
    Environment = var.environment
  }
}

# IAM policy for maintenance scheduler
resource "aws_iam_role_policy" "maintenance_scheduler_policy" {
  name = "MaintenanceSchedulerPolicy"
  role = aws_iam_role.maintenance_scheduler_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:PutItem"
        ]
        Resource = aws_dynamodb_table.patch_execution_state.arn
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.patch_deduplication.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# VPC execution policy for maintenance scheduler Lambda
resource "aws_iam_role_policy_attachment" "maintenance_scheduler_vpc_execution" {
  role       = aws_iam_role.maintenance_scheduler_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# CloudWatch Log Group for Maintenance Scheduler
resource "aws_cloudwatch_log_group" "maintenance_scheduler_logs" {
  name              = "/aws/lambda/patch-maintenance-scheduler"
  retention_in_days = 7
  
  tags = {
    Name        = "MaintenanceSchedulerLogs"
    Environment = var.environment
  }
}


# Dead Letter Queue for Lambda failures
resource "aws_sqs_queue" "lambda_dlq" {
  name              = "patch-automation-dlq"
  kms_master_key_id = aws_kms_key.patch_automation_key.id
  
  tags = {
    Name        = "PatchAutomationDLQ"
    Environment = var.environment
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/patch-deduplication-function"
  retention_in_days = 7
  
  tags = {
    Name        = "PatchDeduplicationLogs"
    Environment = var.environment
  }
}

# SSM Document
resource "aws_ssm_document" "improved_patch_automation" {
  name            = "ImprovedPatchAutomation"
  document_type   = "Automation"
  document_format = "YAML"
  content         = file("${path.module}/../documents/improved-patch-automation-final.yaml")
  
  tags = {
    Name        = "ImprovedPatchAutomation"
    Environment = var.environment
  }
}

# EventBridge Rule for Inspector findings
resource "aws_cloudwatch_event_rule" "inspector_findings" {
  name        = "inspector-vulnerability-findings"
  description = "Trigger on high and critical Inspector findings"
  
  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
    detail = {
      severity = ["HIGH", "CRITICAL", "MEDIUM"]
      status   = ["ACTIVE"]
      type     = ["PACKAGE_VULNERABILITY", "NETWORK_REACHABILITY"]
    }
  })
  
  tags = {
    Name        = "InspectorFindingsRule"
    Environment = var.environment
  }
}

# EventBridge Rule for Maintenance Window Scheduler
resource "aws_cloudwatch_event_rule" "maintenance_scheduler" {
  name                = "patch-maintenance-scheduler"
  description         = "Trigger scheduled patches during maintenance window"
  schedule_expression = "cron(0 13-20 * * ? *)"  # Every hour from 1 PM to 7 PM UTC
  
  tags = {
    Name        = "MaintenanceSchedulerRule"
    Environment = var.environment
  }
}

# EventBridge Target for Inspector findings
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.inspector_findings.name
  target_id = "PatchDeduplicationLambda"
  arn       = aws_lambda_function.patch_deduplication.arn
}

# EventBridge Target for Maintenance Scheduler
resource "aws_cloudwatch_event_target" "maintenance_scheduler_target" {
  rule      = aws_cloudwatch_event_rule.maintenance_scheduler.name
  target_id = "MaintenanceSchedulerLambda"
  arn       = aws_lambda_function.maintenance_scheduler.arn
}

# Lambda permission for EventBridge (Inspector findings)
resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.patch_deduplication.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.inspector_findings.arn
}

# Lambda permission for EventBridge (Maintenance scheduler)
resource "aws_lambda_permission" "maintenance_scheduler_eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvokeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.maintenance_scheduler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.maintenance_scheduler.arn
}

# CloudWatch Log Group for SSM
resource "aws_cloudwatch_log_group" "ssm_patch_logs" {
  name              = "/aws/ssm/patch-automation"
  retention_in_days = 30
  
  tags = {
    Name        = "SSMPatchLogs"
    Environment = var.environment
  }
}

# Inspector enabler
resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR"]
}

# IAM role for EC2 instances (for SSM)
resource "aws_iam_role" "ec2_ssm_role" {
  name = "EC2-SSM-Role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name        = "EC2SSMRole"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "ec2_ssm_policy" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "EC2-SSM-Profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Enhanced CloudWatch Dashboard with security metrics
resource "aws_cloudwatch_dashboard" "patch_monitoring" {
  dashboard_name = "patch-automation-monitoring"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.patch_deduplication.function_name, { stat = "Sum", label = "Deduplication Invocations" }],
            [".", "Errors", ".", ".", { stat = "Sum", label = "Deduplication Errors" }],
            [".", "Duration", ".", ".", { stat = "Average", label = "Deduplication Avg Duration" }],
            [".", "Invocations", "FunctionName", aws_lambda_function.maintenance_scheduler.function_name, { stat = "Sum", label = "Scheduler Invocations" }],
            [".", "Errors", ".", ".", { stat = "Sum", label = "Scheduler Errors" }],
            [".", "Duration", ".", ".", { stat = "Average", label = "Scheduler Avg Duration" }]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Lambda Function Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          query   = <<-EOT
            SOURCE '/aws/lambda/patch-deduplication-function'
            | fields @timestamp, @message
            | filter @message like /ERROR/
            | sort @timestamp desc
            | limit 20
          EOT
          region  = var.aws_region
          title   = "Recent Errors"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        
        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.patch_execution_state.name],
            [".", "ConsumedWriteCapacityUnits", ".", "."],
            [".", "UserErrors", ".", "."],
            [".", "SystemErrors", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "DynamoDB Metrics"
          period  = 300
        }
      }
    ]
  })
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "patch-automation-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors lambda errors"
  alarm_actions       = [aws_sns_topic.patch_notifications.arn]
  
  dimensions = {
    FunctionName = aws_lambda_function.patch_deduplication.function_name
  }
  
  tags = {
    Name        = "PatchAutomationLambdaErrors"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "dynamodb_errors" {
  alarm_name          = "patch-automation-dynamodb-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors DynamoDB user errors"
  alarm_actions       = [aws_sns_topic.patch_notifications.arn]
  
  dimensions = {
    TableName = aws_dynamodb_table.patch_execution_state.name
  }
  
  tags = {
    Name        = "PatchAutomationDynamoDBErrors"
    Environment = var.environment
  }
}