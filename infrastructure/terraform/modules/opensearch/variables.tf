variable "vpc_id" {
  description = "VPC ID where the OpenSearch domain will be created"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the OpenSearch domain"
  type        = list(string)
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
}

variable "instance_type" {
  description = "OpenSearch instance type"
  type        = string
  default     = "r6g.large.search"
}

variable "instance_count" {
  description = "Number of data nodes in the cluster"
  type        = number
  default     = 3
}

variable "volume_size" {
  description = "EBS volume size in GB for each data node"
  type        = number
  default     = 100
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
