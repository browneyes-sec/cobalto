terraform {
  required_version = ">= 1.6"

  backend "s3" {
    bucket         = "cobalto-tf-state"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "cobalto-tf-locks"
  }
}

module "cobalto" {
  source = "../../"

  aws_region      = "us-east-1"
  vpc_cidr        = "10.0.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b"]

  eks_cluster_version    = "1.29"
  eks_node_instance_types = ["t3.medium"]
  eks_node_desired_size   = 2
  eks_node_min_size       = 1
  eks_node_max_size       = 4

  rds_instance_class          = "db.t3.medium"
  rds_allocated_storage       = 50
  rds_multi_az                = false
  rds_backup_retention_period = 7
  rds_skip_final_snapshot     = true

  redis_node_type       = "cache.t3.medium"
  redis_num_cache_nodes = 1

  mq_instance_type = "mq.t3.micro"

  opensearch_instance_type  = "t3.small.search"
  opensearch_instance_count = 1

  acm_certificate_arn = ""
}
