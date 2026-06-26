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
    Module    = "opensearch"
  })
  name_prefix = "cobalto-${var.environment}"
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_kms_key" "opensearch" {
  description             = "KMS key for OpenSearch encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "opensearch" {
  name          = "alias/${local.name_prefix}-opensearch"
  target_key_id = aws_kms_key.opensearch.key_id
}

resource "aws_security_group" "this" {
  name_prefix = "${local.name_prefix}-opensearch-"
  description = "Security group for OpenSearch - ${local.name_prefix}"
  vpc_id      = var.vpc_id

  ingress {
    description = "OpenSearch API from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  ingress {
    description = "OpenSearch from VPC"
    from_port   = 9200
    to_port     = 9200
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
    Name = "${local.name_prefix}-opensearch-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_opensearch_domain" "this" {
  domain_name    = "${local.name_prefix}-opensearch"
  engine_version = "2.11"

  cluster_config {
    instance_type  = var.instance_type
    instance_count = var.instance_count

    zone_awareness_enabled = var.instance_count >= 2 ? true : false
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.volume_size
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.opensearch.arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  access_policies = data.aws_iam_policy_document.opensearch.json

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    enabled                  = true
    log_type                 = "ES_APPLICATION_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_index.arn
    enabled                  = true
    log_type                 = "INDEX_SLOW_LOGS"
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_search.arn
    enabled                  = true
    log_type                 = "SEARCH_SLOW_LOGS"
  }

  tags = local.common_tags

  lifecycle {
    ignore_changes = [vpc_options]
  }
}

data "aws_iam_policy_document" "opensearch" {
  statement {
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["es:*"]
    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${local.name_prefix}-opensearch/*"]
  }

  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
    actions   = ["es:ESHttp*"]
    resources = ["arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${local.name_prefix}-opensearch/*"]
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/${local.name_prefix}-opensearch/application-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.opensearch.arn
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "opensearch_index" {
  name              = "/aws/opensearch/${local.name_prefix}-opensearch/index-slow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.opensearch.arn
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "opensearch_search" {
  name              = "/aws/opensearch/${local.name_prefix}-opensearch/search-slow-logs"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.opensearch.arn
  tags              = local.common_tags
}

resource "aws_iam_role" "opensearch" {
  name_prefix = "${local.name_prefix}-opensearch-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "opensearch.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "opensearch" {
  role       = aws_iam_role.opensearch.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonOpenSearchServiceFullAccess"
}
