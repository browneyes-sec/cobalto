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
  })
}

resource "aws_security_group" "alb" {
  name        = "${var.environment}-cobalto-alb-sg"
  description = "Security group for Cobalto SOC/MDR platform ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-alb-sg"
  })
}

resource "aws_lb" "this" {
  name               = "${var.environment}-cobalto-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = var.environment == "prod" ? true : false

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "${var.environment}-cobalto-alb"
    enabled = true
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-alb"
  })
}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "${var.environment}-cobalto-alb-logs"

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-alb-logs"
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowALBLogging"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_elb_service_account.main.id}:root"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/${var.environment}-cobalto-alb/*"
      },
      {
        Sid    = "AllowALBLogDelivery"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/${var.environment}-cobalto-alb/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AllowALBLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

data "aws_elb_service_account" "main" {}

# Target Groups
resource "aws_lb_target_group" "n8n" {
  name        = "${var.environment}-cobalto-n8n"
  port        = 5678
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/healthz"
    port                = "traffic-port"
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-n8n-tg"
  })
}

resource "aws_lb_target_group" "opencti" {
  name        = "${var.environment}-cobalto-opencti"
  port        = 4000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    port                = "traffic-port"
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-opencti-tg"
  })
}

resource "aws_lb_target_group" "thehive" {
  name        = "${var.environment}-cobalto-thehive"
  port        = 9000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/api/v1/status/public"
    port                = "traffic-port"
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-thehive-tg"
  })
}

resource "aws_lb_target_group" "grafana" {
  name        = "${var.environment}-cobalto-grafana"
  port        = 3000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/api/health"
    port                = "traffic-port"
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-grafana-tg"
  })
}

resource "aws_lb_target_group" "langgraph_api" {
  name        = "${var.environment}-cobalto-langgraph-api"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    port                = "traffic-port"
    matcher             = "200"
  }

  tags = merge(local.common_tags, {
    Name = "${var.environment}-cobalto-langgraph-api-tg"
  })
}

# HTTPS Listener
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.n8n.arn
  }

  tags = local.common_tags
}

# HTTP Listener (redirect to HTTPS)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = local.common_tags
}

# Listener Rules for path-based routing
resource "aws_lb_listener_rule" "opencti" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.opencti.arn
  }

  condition {
    path_pattern {
      values = ["/opencti*", "/opencti/*"]
    }
  }
}

resource "aws_lb_listener_rule" "thehive" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 110

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.thehive.arn
  }

  condition {
    path_pattern {
      values = ["/thehive*", "/thehive/*"]
    }
  }
}

resource "aws_lb_listener_rule" "grafana" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 120

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.grafana.arn
  }

  condition {
    path_pattern {
      values = ["/grafana*", "/grafana/*"]
    }
  }
}

resource "aws_lb_listener_rule" "langgraph_api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 130

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.langgraph_api.arn
  }

  condition {
    path_pattern {
      values = ["/api*", "/api/*"]
    }
  }
}
