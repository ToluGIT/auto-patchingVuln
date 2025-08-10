output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.patch_deduplication.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.patch_deduplication.arn
}

output "automation_document_name" {
  description = "Name of the SSM automation document"
  value       = aws_ssm_document.improved_patch_automation.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = aws_sns_topic.patch_notifications.arn
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB state table"
  value       = aws_dynamodb_table.patch_execution_state.name
}

output "vpc_id" {
  description = "ID of the VPC created for the patch automation system"
  value       = aws_vpc.patch_automation_vpc.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.lambda_subnet[*].id
}

output "security_group_id" {
  description = "ID of the Lambda security group"
  value       = aws_security_group.lambda_sg.id
}

output "dashboard_url" {
  description = "URL to the CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.patch_monitoring.dashboard_name}"
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile for SSM"
  value       = aws_iam_instance_profile.ec2_ssm_profile.name
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.patch_automation_key.id
}