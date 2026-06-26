output "endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.this.endpoint
}

output "port" {
  description = "RDS instance port"
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Database name"
  value       = aws_db_instance.this.db_name
}

output "security_group_id" {
  description = "Security group ID attached to RDS"
  value       = aws_security_group.this.id
}

output "instance_id" {
  description = "RDS instance identifier"
  value       = aws_db_instance.this.id
}
