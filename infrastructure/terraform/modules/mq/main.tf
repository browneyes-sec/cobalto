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
    Module    = "mq"
  })
  name_prefix = "cobalto-${var.environment}"
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_kms_key" "mq" {
  description             = "KMS key for Amazon MQ encryption - ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "mq" {
  name          = "alias/${local.name_prefix}-mq"
  target_key_id = aws_kms_key.mq.key_id
}

resource "aws_security_group" "this" {
  name_prefix = "${local.name_prefix}-mq-"
  description = "Security group for Amazon MQ - ${local.name_prefix}"
  vpc_id      = var.vpc_id

  ingress {
    description = "AMQP from VPC"
    from_port   = 5671
    to_port     = 5671
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  ingress {
    description = "MQTT from VPC"
    from_port   = 8883
    to_port     = 8883
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  ingress {
    description = "Management console from VPC"
    from_port   = 8162
    to_port     = 8162
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
    Name = "${local.name_prefix}-mq-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_mq_broker" "this" {
  broker_name = "${local.name_prefix}-rabbitmq"

  engine_type        = "RabbitMQ"
  engine_version     = "3.13"
  host_instance_type = var.instance_type
  deployment_mode    = var.deployment_mode

  user {
    username = "cobalto_admin"
    password = random_password.mq_password.result
  }

  storage_type = "ebs"
  storage_volume {
    master_user_password                 = random_password.mq_password.result
    kms_key_id                           = aws_kms_key.mq.arn
    provisioned_throughput {
      enabled = false
    }
  }

  subnet_ids                  = var.deployment_mode == "SINGLE_INSTANCE" ? [var.subnet_ids[0]] : var.subnet_ids
  security_groups             = [aws_security_group.this.id]
  auto_minor_version_upgrade  = true
  apply_immediately           = false
  publicly_accessible         = false
  encryption_options {
    use_aws_owned_key = false
    kms_key_id        = aws_kms_key.mq.arn
  }

  logs {
    general = true
  }

  tags = local.common_tags
}

resource "random_password" "mq_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}|:?"
}
