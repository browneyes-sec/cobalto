locals {
  env       = terraform.workspace
  region    = var.aws_region
  project   = "cobalto"
  tags = {
    Project   = local.project
    ManagedBy = "terraform"
    Environment = local.env
  }
}

provider "aws" {
  region = local.region

  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.tags
  }
}

# KMS - shared encryption key
module "kms" {
  source = "./modules/kms"

  project     = local.project
  environment = local.env
  tags        = local.tags
}

# VPC
module "vpc" {
  source = "./modules/vpc"

  project             = local.project
  environment         = local.env
  vpc_cidr            = var.vpc_cidr
  availability_zones  = var.availability_zones
  tags                = local.tags
}

# EKS
module "eks" {
  source = "./modules/eks"

  project            = local.project
  environment        = local.env
  cluster_version    = var.eks_cluster_version
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  node_instance_types = var.eks_node_instance_types
  node_desired_size   = var.eks_node_desired_size
  node_min_size       = var.eks_node_min_size
  node_max_size       = var.eks_node_max_size
  kms_key_arn        = module.kms.key_arn
  tags               = local.tags

  depends_on = [module.vpc, module.kms]
}

# RDS - PostgreSQL
module "rds" {
  source = "./modules/rds"

  project                = local.project
  environment            = local.env
  vpc_id                 = module.vpc.vpc_id
  private_subnet_ids     = module.vpc.private_subnet_ids
  eks_security_group_id  = module.eks.node_security_group_id
  instance_class         = var.rds_instance_class
  allocated_storage      = var.rds_allocated_storage
  multi_az               = var.rds_multi_az
  backup_retention_period = var.rds_backup_retention_period
  skip_final_snapshot    = var.rds_skip_final_snapshot
  kms_key_arn            = module.kms.key_arn
  tags                   = local.tags

  depends_on = [module.vpc, module.eks, module.kms]
}

# ElastiCache Redis
module "redis" {
  source = "./modules/elasticache"

  project               = local.project
  environment           = local.env
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  eks_security_group_id = module.eks.node_security_group_id
  node_type             = var.redis_node_type
  num_cache_nodes       = var.redis_num_cache_nodes
  kms_key_arn           = module.kms.key_arn
  tags                  = local.tags

  depends_on = [module.vpc, module.eks, module.kms]
}

# Amazon MQ (RabbitMQ)
module "mq" {
  source = "./modules/mq"

  project               = local.project
  environment           = local.env
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  eks_security_group_id = module.eks.node_security_group_id
  instance_type         = var.mq_instance_type
  kms_key_arn           = module.kms.key_arn
  tags                  = local.tags

  depends_on = [module.vpc, module.eks, module.kms]
}

# OpenSearch
module "opensearch" {
  source = "./modules/opensearch"

  project               = local.project
  environment           = local.env
  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  eks_security_group_id = module.eks.node_security_group_id
  instance_type         = var.opensearch_instance_type
  instance_count        = var.opensearch_instance_count
  kms_key_arn           = module.kms.key_arn
  tags                  = local.tags

  depends_on = [module.vpc, module.eks, module.kms]
}

# S3 - application buckets
module "s3" {
  source = "./modules/s3"

  project     = local.project
  environment = local.env
  kms_key_arn = module.kms.key_arn
  tags        = local.tags

  depends_on = [module.kms]
}

# ALB - application load balancer
module "alb" {
  source = "./modules/alb"

  project               = local.project
  environment           = local.env
  vpc_id                = module.vpc.vpc_id
  public_subnet_ids     = module.vpc.public_subnet_ids
  eks_security_group_id = module.eks.node_security_group_id
  certificate_arn       = var.acm_certificate_arn
  tags                  = local.tags

  depends_on = [module.vpc, module.eks]
}
