output "primary_endpoint" {
  description = "Primary endpoint for the Redis replication group"
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "port" {
  description = "Redis port"
  value       = aws_elasticache_replication_group.this.port
}

output "security_group_id" {
  description = "Security group ID attached to ElastiCache"
  value       = aws_security_group.this.id
}

output "replication_group_id" {
  description = "Replication group identifier"
  value       = aws_elasticache_replication_group.this.id
}
