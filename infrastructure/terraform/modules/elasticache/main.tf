terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  common_tags = merge(var.tags, {
    Project   = "cobalto"
    ManagedBy = "terraform"
    Module    = "elasticache"
  })
  name_prefix = "cobalto-${var.environment}"
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_kms_key" "elasticache" {
  description             = "KMS key for ElastiCache encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "elasticache" {
  name          = "alias/${local.name_prefix}-elasticache"
  target_key_id = aws_kms_key.elasticache.key_id
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${local.name_prefix}-elasticache-subnet-group"
  subnet_ids = var.subnet_ids
  tags       = local.common_tags
}

resource "aws_security_group" "this" {
  name_prefix = "${local.name_prefix}-elasticache-"
  description = "Security group for ElastiCache Redis - ${local.name_prefix}"
  vpc_id      = var.vpc_id

  ingress {
    description = "Redis from VPC"
    from_port   = var.port
    to_port     = var.port
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-elasticache-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "Redis replication group for ${local.name_prefix}"

  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_clusters
  port                 = var.port

  automatic_failover_enabled = true
  multi_az_enabled           = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.elasticache.arn

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.this.id]

  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"

  auto_minor_version_upgrade = true

  tags = local.common_tags
}
