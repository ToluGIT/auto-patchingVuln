variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "notification_email" {
  description = "Email address for patch notifications"
  type        = string
  validation {
    condition     = can(regex("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Please provide a valid email address."
  }
}

variable "maintenance_window_start" {
  description = "Start hour for maintenance window (24-hour format)"
  type        = number
  default     = 2
  validation {
    condition     = var.maintenance_window_start >= 0 && var.maintenance_window_start <= 23
    error_message = "Maintenance window start must be between 0 and 23."
  }
}

variable "maintenance_window_end" {
  description = "End hour for maintenance window (24-hour format)"
  type        = number
  default     = 5
  validation {
    condition     = var.maintenance_window_end >= 0 && var.maintenance_window_end <= 23
    error_message = "Maintenance window end must be between 0 and 23."
  }
}

variable "enable_snapshot_before_patch" {
  description = "Create EBS snapshots before patching"
  type        = bool
  default     = true
}

variable "project_name" {
  description = "Project name for resource naming and tagging"
  type        = string
  default     = "vulnerability-automation"
}