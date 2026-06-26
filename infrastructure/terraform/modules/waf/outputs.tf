output "web_acl_arn" {
  description = "ARN of the WAF v2 Web ACL"
  value       = aws_wafv2_web_acl.this.arn
}

output "web_acl_id" {
  description = "ID of the WAF v2 Web ACL"
  value       = aws_wafv2_web_acl.this.id
}

output "web_acl_name" {
  description = "Name of the WAF v2 Web ACL"
  value       = aws_wafv2_web_acl.this.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for WAF logs"
  value       = aws_cloudwatch_log_group.waf.arn
}
