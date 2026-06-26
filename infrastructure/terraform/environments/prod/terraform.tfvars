aws_region      = "us-east-1"
vpc_cidr        = "10.2.0.0/16"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

eks_cluster_version    = "1.29"
eks_node_instance_types = ["m5.xlarge", "m5.2xlarge"]
eks_node_desired_size   = 5
eks_node_min_size       = 3
eks_node_max_size       = 10

rds_instance_class          = "db.r5.xlarge"
rds_allocated_storage       = 200
rds_multi_az                = true
rds_backup_retention_period = 30
rds_skip_final_snapshot     = false

redis_node_type       = "cache.r5.large"
redis_num_cache_nodes = 3

mq_instance_type = "mq.m5.xlarge"

opensearch_instance_type  = "m5.xlarge.search"
opensearch_instance_count = 3

acm_certificate_arn = ""
