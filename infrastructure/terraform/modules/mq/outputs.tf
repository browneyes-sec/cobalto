output "amqp_endpoint" {
  description = "AMQP endpoint for the RabbitMQ broker"
  value       = aws_mq_broker.this.instances[0].endpoints[0]
}

output "console_endpoint" {
  description = "Management console endpoint"
  value       = aws_mq_broker.this.instances[0].console_url
}

output "security_group_id" {
  description = "Security group ID attached to Amazon MQ"
  value       = aws_security_group.this.id
}

output "broker_id" {
  description = "Amazon MQ broker ID"
  value       = aws_mq_broker.this.broker_id
}
