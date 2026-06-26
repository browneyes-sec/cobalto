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

resource "aws_s3_bucket" "this" {
  for_each = {
    soc-telemetry-raw = "soc-telemetry-raw"
    soc-threat-intel  = "soc-threat-intel"
    soc-model-artifacts = "soc-model-artifacts"
  }

  bucket = "${var.environment}-${each.value}"

  tags = merge(local.common_tags, {
    Name = "${var.environment}-${each.value}"
  })
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3[each.key].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_kms_key" "s3" {
  for_each = aws_s3_bucket.this

  description             = "KMS key for S3 bucket ${each.key}"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name    = "${var.environment}-${each.key}-kms"
    Purpose = "s3-encryption"
  })
}

resource "aws_kms_alias" "s3" {
  for_each = aws_kms_key.s3

  name          = "alias/${var.environment}-s3-${each.key}"
  target_key_id = each.value.key_id
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = aws_s3_bucket.this

  bucket = each.value.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "telemetry" {
  bucket = aws_s3_bucket.this["soc-telemetry-raw"].id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}
