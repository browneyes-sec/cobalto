variable "alb_arn" {
  description = "ARN of the ALB to associate with the WAF"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string

  validation {
    condition     = can(regex("^(dev|staging|prod)$", var.environment))
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "enable_geo_blocking" {
  description = "Enable geo blocking rule"
  type        = bool
  default     = false
}

variable "blocked_countries" {
  description = "List of ISO 3166-1 alpha-2 country codes to block"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for code in var.blocked_countries : can(regex("^[A-Z]{2}$", code))])
    error_message = "All country codes must be valid 2-letter ISO 3166-1 alpha-2 codes."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
