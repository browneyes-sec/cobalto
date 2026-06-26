aws_region      = "us-east-1"
vpc_cidr        = "10.1.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b"]

eks_cluster_version    = "1.29"
eks_node_instance_types = ["m5.large"]
eks_node_desired_size   = 3
eks_node_min_size       = 2
eks_node_max_size       = 6

rds_instance_class          = "db.m5.large"
rds_allocated_storage       = 100
rds_multi_az                = true
rds_backup_retention_period = 14
rds_skip_final_snapshot     = true

redis_node_type       = "cache.m5.large"
redis_num_cache_nodes = 2

mq_instance_type = "mq.m5.large"

opensearch_instance_type  = "m5.large.search"
opensearch_instance_count = 2

acm_certificate_arn = ""
