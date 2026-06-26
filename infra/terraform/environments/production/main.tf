module "cobalto" {
  source = "../"

  aws_region         = "us-east-1"
  environment        = "production"
  project_name       = "cobalto"
  eks_cluster_version = "1.29"
  single_nat_gateway = false
}

# =============================================================================
# Namespace Isolation for Production Tenants
# =============================================================================

module "tenant_namespace" {
  source = "../../modules/namespace-isolation"

  for_each = {
    "acme-corp" = {
      tenant_id = "tenant-acme-001"
      namespace = "cobalto-acme-corp"
      labels = {
        "tenant.io/name"     = "acme-corp"
        "tenant.io/tier"     = "enterprise"
        "tenant.io/region"   = "us-east-1"
      }
      resource_quota = {
        requests_cpu    = "8"
        requests_memory = "16Gi"
        limits_cpu      = "16"
        limits_memory   = "32Gi"
        pods            = 100
        services        = 30
        secrets         = 100
        configmaps      = 100
        pvcs            = 20
      }
    }

    "global-bank" = {
      tenant_id = "tenant-gbank-002"
      namespace = "cobalto-global-bank"
      labels = {
        "tenant.io/name"     = "global-bank"
        "tenant.io/tier"     = "enterprise"
        "tenant.io/region"   = "us-east-1"
        "tenant.io/compliance" = "pci-dss"
      }
      resource_quota = {
        requests_cpu    = "16"
        requests_memory = "32Gi"
        limits_cpu      = "32"
        limits_memory   = "64Gi"
        pods            = 200
        services        = 50
        secrets         = 200
        configmaps      = 200
        pvcs            = 50
      }
    }
  }

  cluster_name    = module.cobalto.cluster_name
  environment     = "production"
  tenant_id       = each.value.tenant_id
  namespace       = each.value.namespace
  labels          = each.value.labels
  resource_quota  = each.value.resource_quota

  network_policy_enabled   = true
  pod_security_standard    = "restricted"
  allowed_namespaces       = ["cobalto-system", "monitoring"]
}

# =============================================================================
# Outputs
# =============================================================================

output "tenant_namespaces" {
  description = "Tenant namespace names"
  value       = { for k, v in module.tenant_namespace : k => v.namespace_name }
}

output "tenant_quotas" {
  description = "Tenant resource quotas"
  value       = { for k, v in module.tenant_namespace : k => v.resource_quota_name }
}
