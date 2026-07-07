# Infrastructure

## Overview

Cobalto deploys on AWS EKS with Terraform for IaC and Helm for Kubernetes resources. Multi-tenant isolation via namespaces, network policies, and resource quotas.

```
+----------------------------------------------------+
|                    AWS Cloud                        |
|                                                    |
|  +----------------------------------------------+  |
|  | EKS Cluster                                  |  |
|  |                                              |  |
|  |  +------------------+  +------------------+  |  |
|  |  | cobalto-system   |  | monitoring       |  |  |
|  |  | (shared svc)     |  | (grafana/prom)   |  |  |
|  |  +------------------+  +------------------+  |  |
|  |                                              |  |
|  |  +------------------+  +------------------+  |  |
|  |  | tenant-acme      |  | tenant-gbank     |  |  |
|  |  | (isolated)       |  | (isolated)       |  |  |
|  |  +------------------+  +------------------+  |  |
|  +----------------------------------------------+  |
|                                                    |
|  +----------------------------------------------+  |
|  | RDS (PostgreSQL)    | ElastiCache (Redis)   |  |
|  +----------------------------------------------+  |
|  | S3 (logs/artifacts) | KMS (encryption)      |  |
|  +----------------------------------------------+  |
+----------------------------------------------------+
```

## Terraform Modules

### Root Module

```
infra/terraform/
├── main.tf              # VPC, EKS, RDS, Redis, S3, KMS
├── variables.tf         # Input variables
└── environments/
    ├── staging/main.tf  # Staging config
    └── production/main.tf  # Production config
```

### Namespace Isolation Module

```
infra/terraform/modules/namespace-isolation/
└── main.tf              # Namespace, quotas, policies
```

## EKS Cluster

### Node Groups

| Name | Instance | Min | Max | Purpose |
|------|----------|-----|-----|---------|
| `system` | t3.medium | 2 | 4 | System services |
| `workload` | m5.large | 2 | 10 | Application pods |

### Addons

- CoreDNS
- kube-proxy
- VPC CNI
- AWS EBS CSI Driver

## Namespace Isolation

### Network Policies

```yaml
# Default deny all
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress

# Allow DNS
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP

# Allow same namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}
  egress:
    - to:
        - podSelector: {}
```

### Resource Quotas

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-quota
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    pods: "100"
    services: "30"
    secrets: "100"
    configmaps: "100"
```

### Limit Ranges

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: tenant-limits
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 512Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "2"
        memory: 4Gi
      min:
        cpu: 50m
        memory: 64Mi
```

## Helm Chart

### Structure

```
infra/kubernetes/charts/cobalto/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── langgraph.yaml   # Deployment, Service, SA
    ├── n8n.yaml         # Deployment, Service, PVC
    ├── secrets.yaml     # Secrets, ExternalSecrets
    ├── hpa.yaml         # HPA, PDB
    └── ingress.yaml     # Ingress, ServiceMonitor
```

### Installation

```bash
# Install chart
helm install cobalto ./infra/kubernetes/charts/cobalto \
  --namespace cobalto-system \
  --create-namespace \
  --values values-production.yaml

# Upgrade
helm upgrade cobalto ./infra/kubernetes/charts/cobalto \
  --namespace cobalto-system \
  --values values-production.yaml

# Uninstall
helm uninstall cobalto --namespace cobalto-system
```

### Values

```yaml
# values-production.yaml
langgraph:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi

n8n:
  replicaCount: 2
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: soc.cobalto.io
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: cobalto-tls
      hosts:
        - soc.cobalto.io
```

## Docker Compose (Local)

### Services

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache |
| RabbitMQ | 5672 | Message queue |
| OpenSearch | 9200 | Search |
| Wazuh Manager | 55000 | SIEM |
| OpenCTI | 4000 | Threat intel |
| TheHive | 9000 | Case mgmt |
| Cortex | 9001 | Enrichment |
| n8n | 5678 | SOAR |
| Qdrant | 6333 | Vector DB |
| Grafana | 3000 | Dashboards |
| Prometheus | 9090 | Metrics |
| Vault | 8200 | Secrets |
| LangGraph API | 8001 | Agent service |

### Usage

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f langgraph-api

# Stop services
docker compose down

# Stop and remove volumes
docker compose down -v
```

## Deployment

### Staging

```bash
# Terraform
cd infra/terraform/environments/staging
terraform init
terraform plan
terraform apply

# Helm
helm install cobalto-staging ./infra/kubernetes/charts/cobalto \
  --namespace cobalto-staging \
  --values values-staging.yaml
```

### Production

```bash
# Terraform
cd infra/terraform/environments/production
terraform init
terraform plan
terraform apply

# Helm
helm install cobalto ./infra/kubernetes/charts/cobalto \
  --namespace cobalto-system \
  --values values-production.yaml
```

## Monitoring

### Grafana Dashboards

- Agent performance
- Alert volume
- Response times
- Error rates

### Prometheus Alerts

- High error rate
- Memory usage
- Pod restarts
- SLA violations

## Configuration

```bash
# AWS
AWS_REGION=us-east-1
AWS_PROFILE=cobalto

# Kubernetes
KUBECONFIG=~/.kube/config
EKS_CLUSTER_NAME=cobalto-cluster

# Helm
HELM_RELEASE=cobalto
HELM_NAMESPACE=cobalto-system
```
