module "cobalto" {
  source = "../"

  aws_region         = "us-east-1"
  environment        = "staging"
  project_name       = "cobalto"
  eks_cluster_version = "1.29"
  single_nat_gateway = true
}