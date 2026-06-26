output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.this.arn
}

output "alb_id" {
  description = "ID of the Application Load Balancer"
  value       = aws_lb.this.id
}

output "dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.this.dns_name
}

output "zone_id" {
  description = "Route 53 zone ID of the Application Load Balancer"
  value       = aws_lb.this.zone_id
}

output "security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "target_group_arns" {
  description = "Map of target group names to their ARNs"
  value = {
    n8n          = aws_lb_target_group.n8n.arn
    opencti      = aws_lb_target_group.opencti.arn
    thehive      = aws_lb_target_group.thehive.arn
    grafana      = aws_lb_target_group.grafana.arn
    langgraph-api = aws_lb_target_group.langgraph_api.arn
  }
}

output "target_group_arns_list" {
  description = "List of all target group ARNs"
  value = [
    aws_lb_target_group.n8n.arn,
    aws_lb_target_group.opencti.arn,
    aws_lb_target_group.thehive.arn,
    aws_lb_target_group.grafana.arn,
    aws_lb_target_group.langgraph_api.arn
  ]
}

output "https_listener_arn" {
  description = "ARN of the HTTPS listener"
  value       = aws_lb_listener.https.arn
}

output "http_listener_arn" {
  description = "ARN of the HTTP listener"
  value       = aws_lb_listener.http.arn
}
