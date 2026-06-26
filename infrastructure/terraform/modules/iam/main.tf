terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  common_tags = merge(var.tags, {
    Project   = "cobalto"
    ManagedBy = "terraform"
  })
}

data "aws_caller_identity" "current" {}

# EKS Cluster Role
resource "aws_iam_role" "eks_cluster" {
  name = "${var.environment}-cobalto-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.environment}-eks-cluster-role"
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster.name
}

# EKS Node Role
resource "aws_iam_role" "eks_nodes" {
  name = "${var.environment}-cobalto-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.environment}-eks-node-role"
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_ecr_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.eks_nodes.name
}

# Node Instance Profile
resource "aws_iam_instance_profile" "eks_nodes" {
  name = "${var.environment}-cobalto-eks-node-profile"
  role = aws_iam_role.eks_nodes.name

  tags = merge(local.common_tags, {
    Name = "${var.environment}-eks-node-profile"
  })
}

# Service Accounts
resource "aws_iam_role" "service_accounts" {
  for_each = toset([
    "langgraph-sa",
    "wazuh-sa",
    "n8n-sa",
    "thehive-sa",
    "opencti-sa"
  ])

  name = "${var.environment}-cobalto-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${var.eks_oidc_issuer}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${var.eks_oidc_issuer}:aud" = "sts.amazonaws.com"
            "${var.eks_oidc_issuer}:sub" = "system:serviceaccount:${var.eks_cluster_name}:${each.key}"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.eks_cluster_name}-${each.key}"
  })
}

# LangGraph S3 and OpenSearch permissions
resource "aws_iam_role_policy" "langgraph_s3_opensearch" {
  name = "${var.environment}-langgraph-s3-opensearch"
  role = aws_iam_role.service_accounts["langgraph-sa"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.environment}-soc-*",
          "arn:aws:s3:::${var.environment}-soc-*/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet",
          "es:ESHttpDelete",
          "es:ESHttpHead"
        ]
        Resource = "arn:aws:es:*:${data.aws_caller_identity.current.account_id}:domain/${var.environment}-cobalto-*"
      }
    ]
  })
}

# Wazuh S3 permissions
resource "aws_iam_role_policy" "wazuh_s3" {
  name = "${var.environment}-wazuh-s3"
  role = aws_iam_role.service_accounts["wazuh-sa"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.environment}-soc-telemetry-raw",
          "arn:aws:s3:::${var.environment}-soc-telemetry-raw/*"
        ]
      }
    ]
  })
}

# n8n S3 permissions
resource "aws_iam_role_policy" "n8n_s3" {
  name = "${var.environment}-n8n-s3"
  role = aws_iam_role.service_accounts["n8n-sa"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.environment}-soc-*",
          "arn:aws:s3:::${var.environment}-soc-*/*"
        ]
      }
    ]
  })
}

# TheHive S3 permissions
resource "aws_iam_role_policy" "thehive_s3" {
  name = "${var.environment}-thehive-s3"
  role = aws_iam_role.service_accounts["thehive-sa"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.environment}-soc-threat-intel",
          "arn:aws:s3:::${var.environment}-soc-threat-intel/*"
        ]
      }
    ]
  })
}

# OpenCTI S3 permissions
resource "aws_iam_role_policy" "opencti_s3" {
  name = "${var.environment}-opencti-s3"
  role = aws_iam_role.service_accounts["opencti-sa"].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.environment}-soc-threat-intel",
          "arn:aws:s3:::${var.environment}-soc-threat-intel/*"
        ]
      }
    ]
  })
}

# Secrets Manager access for all service accounts
resource "aws_iam_role_policy" "secrets_manager" {
  for_each = aws_iam_role.service_accounts

  name = "${var.environment}-${each.key}-secrets"
  role = each.value.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:${var.environment}/cobalto/*"
      }
    ]
  })
}
