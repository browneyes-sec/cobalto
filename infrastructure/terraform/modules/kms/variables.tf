variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string

  validation {
    condition     = can(regex("^(dev|staging|prod)$", var.environment))
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "admins" {
  description = "List of IAM ARNs that have admin access to the KMS key"
  type        = list(string)

  validation {
    condition     = length(var.admins) > 0
    error_message = "At least one admin ARN must be provided."
  }

  validation {
    condition     = alltrue([for arn in var.admins : can(regex("^arn:aws:iam::[0-9]{12}:root$", arn)) || can(regex("^arn:aws:iam::[0-9]{12}:user/.*$", arn)) || can(regex("^arn:aws:iam::[0-9]{12}:role/.*$", arn))])
    error_message = "All admin ARNs must be valid IAM ARNs (root, user, or role)."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
