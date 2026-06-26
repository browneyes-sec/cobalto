output "bucket_ids" {
  description = "Map of bucket names to their IDs"
  value = {
    for k, v in aws_s3_bucket.this : k => v.id
  }
}

output "bucket_arns" {
  description = "Map of bucket names to their ARNs"
  value = {
    for k, v in aws_s3_bucket.this : k => v.arn
  }
}

output "bucket_regional_domain_names" {
  description = "Map of bucket names to their regional domain names"
  value = {
    for k, v in aws_s3_bucket.this : k => v.bucket_regional_domain_name
  }
}
