variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "eks_cluster_version" {
  description = "EKS cluster version"
  type        = string
  default     = "1.29"
}

variable "eks_node_instance_types" {
  description = "EKS node instance types"
  type        = list(string)
}

variable "eks_node_desired_size" {
  description = "EKS node desired size"
  type        = number
}

variable "eks_node_min_size" {
  description = "EKS node min size"
  type        = number
}

variable "eks_node_max_size" {
  description = "EKS node max size"
  type        = number
}

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
}

variable "rds_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
}

variable "rds_multi_az" {
  description = "Enable RDS Multi-AZ"
  type        = bool
}

variable "rds_backup_retention_period" {
  description = "RDS backup retention period in days"
  type        = number
}

variable "rds_skip_final_snapshot" {
  description = "Skip RDS final snapshot on destroy"
  type        = bool
}

variable "redis_node_type" {
  description = "Redis node type"
  type        = string
}

variable "redis_num_cache_nodes" {
  description = "Number of Redis cache nodes"
  type        = number
}

variable "mq_instance_type" {
  description = "Amazon MQ instance type"
  type        = string
}

variable "opensearch_instance_type" {
  description = "OpenSearch instance type"
  type        = string
}

variable "opensearch_instance_count" {
  description = "OpenSearch instance count"
  type        = number
}

variable "acm_certificate_arn" {
  description = "ACM certificate ARN for ALB"
  type        = string
  default     = ""
}
