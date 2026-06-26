output "endpoint" {
  description = "OpenSearch domain endpoint"
  value       = aws_opensearch_domain.this.endpoint
}

output "dashboard_endpoint" {
  description = "OpenSearch Dashboards endpoint"
  value       = aws_opensearch_domain.this.dashboard_endpoint
}

output "security_group_id" {
  description = "Security group ID attached to OpenSearch"
  value       = aws_security_group.this.id
}

output "domain_name" {
  description = "OpenSearch domain name"
  value       = aws_opensearch_domain.this.domain_name
}
