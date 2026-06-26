terraform {
  required_version = ">= 1.7.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "tenant_id" {
  description = "Tenant identifier"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
}

variable "create_namespace" {
  description = "Whether to create the namespace"
  type        = bool
  default     = true
}

variable "labels" {
  description = "Additional labels for the namespace"
  type        = map(string)
  default     = {}
}

variable "annotations" {
  description = "Additional annotations for the namespace"
  type        = map(string)
  default     = {}
}

variable "resource_quota" {
  description = "Resource quota for the namespace"
  type = object({
    requests_cpu    = string
    requests_memory = string
    limits_cpu      = string
    limits_memory   = string
    pods            = number
    services        = number
    secrets         = number
    configmaps      = number
    pvcs            = number
  })
  default = {
    requests_cpu    = "4"
    requests_memory = "8Gi"
    limits_cpu      = "8"
    limits_memory   = "16Gi"
    pods            = 50
    services        = 20
    secrets         = 50
    configmaps      = 50
    pvcs            = 10
  }
}

variable "network_policy_enabled" {
  description = "Enable network policies"
  type        = bool
  default     = true
}

variable "pod_security_standard" {
  description = "Pod security standard (privileged, baseline, restricted)"
  type        = string
  default     = "baseline"

  validation {
    condition     = contains(["privileged", "baseline", "restricted"], var.pod_security_standard)
    error_message = "Pod security standard must be privileged, baseline, or restricted."
  }
}

variable "allowed_namespaces" {
  description = "Namespaces that can communicate with this namespace"
  type        = list(string)
  default     = []
}

# =============================================================================
# Namespace
# =============================================================================

resource "kubernetes_namespace" "tenant" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name = var.namespace

    labels = merge(
      {
        "app.kubernetes.io/managed-by" = "terraform"
        "app.kubernetes.io/part-of"    = "cobalto"
        "cobalto.io/tenant-id"         = var.tenant_id
        "cobalto.io/environment"       = var.environment
        "cobalto.io/cluster"           = var.cluster_name
        "pod-security.kubernetes.io/enforcement" = var.pod_security_standard
      },
      var.labels,
    )

    annotations = merge(
      {
        "cobalto.io/created-by" = "terraform"
      },
      var.annotations,
    )
  }
}

# =============================================================================
# Resource Quotas
# =============================================================================

resource "kubernetes_resource_quota" "tenant" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name      = "${var.tenant_id}-quota"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    hard = {
      "requests.cpu"    = var.resource_quota.requests_cpu
      "requests.memory" = var.resource_quota.requests_memory
      "limits.cpu"      = var.resource_quota.limits_cpu
      "limits.memory"   = var.resource_quota.limits_memory
      "pods"            = var.resource_quota.pods
      "services"        = var.resource_quota.services
      "secrets"         = var.resource_quota.secrets
      "configmaps"      = var.resource_quota.configmaps
      "persistentvolumeclaims" = var.resource_quota.pvcs
    }
  }
}

# =============================================================================
# Limit Ranges
# =============================================================================

resource "kubernetes_limit_range" "tenant" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name      = "${var.tenant_id}-limits"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    limit {
      type = "Container"
      default = {
        cpu    = "500m"
        memory = "512Mi"
      }
      default_request = {
        cpu    = "100m"
        memory = "128Mi"
      }
      max = {
        cpu    = "2"
        memory = "4Gi"
      }
      min = {
        cpu    = "50m"
        memory = "64Mi"
      }
    }

    limit {
      type = "Pod"
      max = {
        cpu    = "4"
        memory = "8Gi"
      }
    }
  }
}

# =============================================================================
# Network Policies
# =============================================================================

resource "kubernetes_network_policy" "default_deny" {
  count = var.create_namespace && var.network_policy_enabled ? 1 : 0

  metadata {
    name      = "default-deny-all"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy" "allow_dns" {
  count = var.create_namespace && var.network_policy_enabled ? 1 : 0

  metadata {
    name      = "allow-dns"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "kube-system"
          }
        }
      }
      ports {
        port     = 53
        protocol = "UDP"
      }
      ports {
        port     = 53
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy" "allow_same_namespace" {
  count = var.create_namespace && var.network_policy_enabled ? 1 : 0

  metadata {
    name      = "allow-same-namespace"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {}
      }
    }

    egress {
      to {
        pod_selector {}
      }
    }
  }
}

resource "kubernetes_network_policy" "allow_from_namespaces" {
  count = var.create_namespace && var.network_policy_enabled && length(var.allowed_namespaces) > 0 ? 1 : 0

  metadata {
    name      = "allow-from-namespaces"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "cobalto-system"
          }
        }
      }
    }
  }
}

resource "kubernetes_network_policy" "allow_to_namespaces" {
  count = var.create_namespace && var.network_policy_enabled && length(var.allowed_namespaces) > 0 ? 1 : 0

  metadata {
    name      = "allow-to-namespaces"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            "kubernetes.io/metadata.name" = "cobalto-system"
          }
        }
      }
    }
  }
}

resource "kubernetes_network_policy" "allow_external_egress" {
  count = var.create_namespace && var.network_policy_enabled ? 1 : 0

  metadata {
    name      = "allow-external-egress"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/component" = "api"
      }
    }
    policy_types = ["Egress"]

    egress {
      to {
        ip_block {
          cidr = "0.0.0.0/0"
          except = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
          ]
        }
      }
    }
  }
}

# =============================================================================
# Pod Security Policies (Legacy)
# =============================================================================

resource "kubernetes_pod_security_policy" "tenant" {
  count = var.create_namespace && var.pod_security_standard == "restricted" ? 1 : 0

  metadata {
    name      = "${var.tenant_id}-psp"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  spec {
    privileged               = false
    allow_privilege_escalation = false
    required_drop_all        = ["ALL"]

    volumes = [
      "configMap",
      "downwardAPI",
      "emptyDir",
      "persistentVolumeClaim",
      "projected",
      "secret",
    ]

    run_as_user {
      rule = "MustRunAsNonRoot"
    }

    se_linux {
      rule = "RunAsAny"
    }

    fs_group {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "RunAsAny"
    }
  }
}

# =============================================================================
# Role Bindings for Tenant
# =============================================================================

resource "kubernetes_role" "tenant_admin" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name      = "${var.tenant_id}-admin"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  rule {
    api_groups = ["", "apps", "batch", "extensions"]
    resources  = ["*"]
    verbs      = ["*"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_role_binding" "tenant_admin" {
  count = var.create_namespace ? 1 : 0

  metadata {
    name      = "${var.tenant_id}-admin-binding"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.tenant_admin[0].metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = kubernetes_namespace.tenant[0].metadata[0].name
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "namespace_name" {
  description = "Namespace name"
  value       = var.create_namespace ? kubernetes_namespace.tenant[0].metadata[0].name : var.namespace
}

output "namespace_id" {
  description = "Namespace ID"
  value       = var.create_namespace ? kubernetes_namespace.tenant[0].metadata[0].uid : ""
}

output "resource_quota_name" {
  description = "Resource quota name"
  value       = var.create_namespace ? kubernetes_resource_quota.tenant[0].metadata[0].name : ""
}

output "network_policies" {
  description = "List of network policies created"
  value = var.network_policy_enabled ? [
    "default-deny-all",
    "allow-dns",
    "allow-same-namespace",
    "allow-external-egress",
  ] : []
}
