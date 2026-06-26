output "eks_cluster_role_arn" {
  description = "ARN of the EKS cluster role"
  value       = aws_iam_role.eks_cluster.arn
}

output "eks_cluster_role_name" {
  description = "Name of the EKS cluster role"
  value       = aws_iam_role.eks_cluster.name
}

output "eks_node_role_arn" {
  description = "ARN of the EKS node role"
  value       = aws_iam_role.eks_nodes.arn
}

output "eks_node_role_name" {
  description = "Name of the EKS node role"
  value       = aws_iam_role.eks_nodes.name
}

output "eks_node_instance_profile_arn" {
  description = "ARN of the EKS node instance profile"
  value       = aws_iam_instance_profile.eks_nodes.arn
}

output "eks_node_instance_profile_name" {
  description = "Name of the EKS node instance profile"
  value       = aws_iam_instance_profile.eks_nodes.name
}

output "service_account_role_arns" {
  description = "Map of service account names to their role ARNs"
  value = {
    for k, v in aws_iam_role.service_accounts : k => v.arn
  }
}

output "service_account_role_names" {
  description = "Map of service account names to their role names"
  value = {
    for k, v in aws_iam_role.service_accounts : k => v.name
  }
}
