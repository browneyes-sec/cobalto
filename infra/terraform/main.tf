terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "s3" {
    bucket         = "cobalto-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cobalto"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  azs        = slice(data.aws_availability_zones.available.names, 0, 3)

  vpc_cidr = "10.0.0.0/16"

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  tags = {
    Environment = var.environment
    Project     = "cobalto"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"

  name = "${var.project_name}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = local.private_subnets
  public_subnets  = local.public_subnets

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment == "development"
  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = "${var.project_name}-cluster"
  cluster_version = var.eks_cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  # Enable IRSA for service accounts
  enable_irsa = true

  # EKS Addons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  # Managed Node Groups
  eks_managed_node_groups = {
    system = {
      name = "system"

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"

      min_size     = 2
      max_size     = 4
      desired_size = 2

      labels = {
        role = "system"
      }

      tags = local.tags
    }

    workload = {
      name = "workload"

      instance_types = ["m5.large", "m5a.large"]
      capacity_type  = "ON_DEMAND"

      min_size     = 2
      max_size     = 10
      desired_size = 3

      labels = {
        role = "workload"
      }

      taints = [{
        key    = "workload"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]

      tags = local.tags
    }
  }

  # Cluster Access
  enable_cluster_creator_admin_permissions = true

  tags = local.tags
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = "${var.project_name}-db"

  engine               = "postgres"
  engine_version       = "16.1"
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.environment == "production" ? "db.r6g.large" : "db.t4g.medium"

  allocated_storage     = var.environment == "production" ? 100 : 20
  max_allocated_storage = var.environment == "production" ? 500 : 100

  db_name  = "cobalto"
  username = "cobalto"
  port     = 5432

  multi_az = var.environment == "production"

  db_subnet_group_name   = module.vpc.database_subnet_group_name
  vpc_security_group_ids = [module.vpc.default_security_group_id]

  backup_retention_period = var.environment == "production" ? 7 : 1
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"

  performance_insights_enabled = true
  monitoring_interval         = 60

  deletion_protection = var.environment == "production"

  tags = local.tags
}

module "redis" {
  source  = "terraform-aws-modules/elasticache/aws"
  version = "~> 1.0"

  replication_group_id = "${var.project_name}-redis"
  description          = "Cobalto Redis cluster"

  engine               = "redis"
  engine_version       = "7.0"
  node_type            = var.environment == "production" ? "cache.r6g.large" : "cache.t4g.medium"
  num_cache_clusters   = var.environment == "production" ? 2 : 1

  automatic_failover_enabled = var.environment == "production"
  multi_az_enabled          = var.environment == "production"

  port = 6379

  vpc_id        = module.vpc.vpc_id
  subnet_ids    = module.vpc.private_subnets

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = local.tags
}

module "s3" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.14"

  for_each = toset(["logs", "artifacts", "models"])

  bucket = "${var.project_name}-${each.key}-${var.environment}"

  force_destroy = var.environment != "production"

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "aws:kms"
      }
    }
  }

  tags = local.tags
}

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 2.0"

  name        = "${var.project_name}-${var.environment}"
  description = "KMS key for Cobalto ${var.environment}"

  key_administrators = [
    "arn:aws:iam::${local.account_id}:root"
  ]

  tags = local.tags
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.db_instance_endpoint
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = module.redis.elasticache_replication_group_primary_endpoint_address
}

output "s3_buckets" {
  description = "S3 bucket names"
  value       = { for k, v in module.s3 : k => v.s3_bucket_id }
}