output "key_arn" {
  description = "ARN of the master KMS key"
  value       = aws_kms_key.master.arn
}

output "key_id" {
  description = "ID of the master KMS key"
  value       = aws_kms_key.master.key_id
}

output "alias_arn" {
  description = "ARN of the KMS alias"
  value       = aws_kms_alias.master.arn
}

output "alias_name" {
  description = "Name of the KMS alias"
  value       = aws_kms_alias.master.name
}
