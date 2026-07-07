# Deployment Runbook

## Overview

This runbook covers deployment procedures for the Cobalto platform across development, staging, and production environments.

## Environments

| Environment | Purpose | Infrastructure | URL |
|-------------|---------|----------------|-----|
| **Development** | Local development | Docker Compose | localhost |
| **Staging** | Pre-production testing | AWS EKS (small) | staging.cobalto.io |
| **Production** | Live environment | AWS EKS (HA) | app.cobalto.io |

## Local Development Setup

### Prerequisites

- Docker Desktop 4.0+
- Python 3.11+
- Git

### Quick Start

```bash
# Clone repository
git clone https://github.com/browneyes-sec/cobalto.git
cd cobalto

# Start all services
docker compose up -d

# Verify services
docker compose ps

# View logs
docker compose logs -f langgraph-api
```

### Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| n8n SOAR | http://localhost:5678 | admin / admin123 |
| TheHive | http://localhost:9000 | admin@cobalto.local / secret |
| OpenCTI | http://localhost:4000 | admin@cobalto.local / Admin123! |
| Grafana | http://localhost:3000 | admin / admin123 |
| LangGraph API | http://localhost:8001 | - |
| Wazuh Dashboard | http://localhost:5601 | admin / admin |

## Staging Deployment

### Prerequisites

- AWS CLI configured
- kubectl configured
- Helm 3.0+

### Steps

```bash
# 1. Configure AWS credentials
aws configure --profile cobalto-staging

# 2. Update kubeconfig
aws eks update-kubeconfig \
  --name cobalto-cluster \
  --region us-east-1 \
  --profile cobalto-staging

# 3. Verify connection
kubectl get nodes
kubectl get pods -n staging

# 4. Deploy with Helm
helm upgrade --install cobalto \
  infra/kubernetes/charts/cobalto \
  --namespace staging \
  --create-namespace \
  --values infra/kubernetes/charts/cobalto/values-staging.yaml \
  --set image.tag=$(git rev-parse HEAD)

# 5. Verify deployment
kubectl get pods -n staging
kubectl get svc -n staging

# 6. Run smoke tests
curl -f http://staging.cobalto.io/health
```

### Rollback

```bash
# Rollback to previous version
helm rollback cobalto -n staging

# Or rollback to specific revision
helm rollback cobalto 5 -n staging
```

## Production Deployment

### Prerequisites

- All staging tests passing
- Change approval from SOC Lead
- Maintenance window scheduled

### Blue-Green Deployment

```bash
# 1. Deploy to green environment
helm upgrade --install cobalto-green \
  infra/kubernetes/charts/cobalto \
  --namespace production \
  --set image.tag=$(git rev-parse HEAD) \
  --set service.name=cobalto-green

# 2. Run smoke tests on green
curl -f http://green.cobalto.io/health

# 3. Switch traffic
kubectl patch ingress cobalto-ingress \
  -p '{"spec":{"rules":[{"host":"app.cobalto.io","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"cobalto-green","port":{"number":80}}}}]}}]}}'

# 4. Monitor for issues
kubectl logs -f deployment/cobalto-green -n production

# 5. If issues, rollback
kubectl patch ingress cobalto-ingress \
  -p '{"spec":{"rules":[{"host":"app.cobalto.io","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"cobalto","port":{"number":80}}}}]}}]}}'
```

### Canary Deployment

```bash
# 1. Deploy canary (10% traffic)
helm upgrade --install cobalto-canary \
  infra/kubernetes/charts/cobalto \
  --namespace production \
  --set image.tag=$(git rev-parse HEAD) \
  --set replicaCount=1 \
  --set canary.enabled=true

# 2. Monitor canary metrics
kubectl port-forward svc/prometheus 9090:9090 -n monitoring

# 3. If healthy, promote to full deployment
helm upgrade --install cobalto \
  infra/kubernetes/charts/cobalto \
  --namespace production \
  --set image.tag=$(git rev-parse HEAD)

# 4. Remove canary
helm uninstall cobalto-canary -n production
```

## Infrastructure Deployment

### Terraform

```bash
# Plan changes
cd infra/terraform/environments/production
terraform plan -out=tfplan

# Apply changes
terraform apply tfplan

# Verify
terraform state list
```

### Kubernetes Manifests

```bash
# Validate manifests
kubectl apply --dry-run=client -f infra/kubernetes/base/

# Apply base manifests
kubectl apply -f infra/kubernetes/base/

# Apply overlay
kubectl apply -k infra/kubernetes/overlays/production/
```

## Multi-Tenant Namespace Isolation

For production deployments with multiple tenants, use the namespace isolation module.

### Deploy Tenant Namespace

```bash
# Using Terraform
cd infra/terraform/environments/production

# Plan tenant namespace
terraform plan -target=module.tenant_namespace["acme-corp"] -out=tfplan

# Apply
terraform apply tfplan
```

### Verify Isolation

```bash
# Check namespace exists
kubectl get namespaces | grep cobalto-

# Check network policies
kubectl get networkpolicies -n cobalto-acme-corp

# Check resource quotas
kubectl get resourcequotas -n cobalto-acme-corp

# Check limit ranges
kubectl get limitranges -n cobalto-acme-corp
```

### Tenant Configuration

Edit `infra/terraform/environments/production/main.tf` to add tenants:

```hcl
module "tenant_namespace" {
  source = "../../modules/namespace-isolation"

  for_each = {
    "new-tenant" = {
      tenant_id = "tenant-new-003"
      namespace = "cobalto-new-tenant"
      labels = {
        "tenant.io/name" = "new-tenant"
        "tenant.io/tier" = "standard"
      }
      resource_quota = {
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
  }

  # ... other config
}
```

## Monitoring & Alerting

### Health Checks

```bash
# Check all services
kubectl get pods -n production -o wide

# Check service health
curl -s http://app.cobalto.io/health | jq .

# Check metrics
curl -s http://app.cobalto.io/metrics | head -20
```

### Grafana Dashboards

Access Grafana at https://grafana.cobalto.io

Key dashboards:
- **SOC Overview**: Alert volume, MTTR, agent performance
- **Infrastructure**: CPU, memory, disk usage
- **Agent Metrics**: Execution time, success rate, error rate

### Prometheus Alerts

Key alerts:
- `HighAlertVolume`: > 100 alerts in 5 minutes
- `AgentFailure`: Agent execution failure rate > 5%
- `HighLatency`: Response time > 30 seconds
- `ServiceDown`: Health check failing

## Troubleshooting

### Common Issues

#### Pod Not Starting

```bash
# Check pod events
kubectl describe pod <pod-name> -n production

# Check logs
kubectl logs <pod-name> -n production --previous

# Check resource limits
kubectl top pod -n production
```

#### Database Connection Issues

```bash
# Test connectivity
kubectl exec -it <pod-name> -n production -- pg_isready -h cobalto-db

# Check secrets
kubectl get secret cobalto-secrets -n production -o yaml
```

#### Memory Issues

```bash
# Check memory usage
kubectl top pods -n production

# Restart pod
kubectl rollout restart deployment/<deployment-name> -n production
```

## Backup & Recovery

### Database Backup

```bash
# Manual backup
kubectl exec -it <postgres-pod> -n production -- \
  pg_dump -U cobalto cobalto > backup-$(date +%Y%m%d).sql

# Restore
kubectl exec -it <postgres-pod> -n production -- \
  psql -U cobalto cobalto < backup-20240101.sql
```

### Elasticsearch Backup

```bash
# Create snapshot
curl -X PUT "http://elasticsearch:9200/_snapshot/cobalto/snapshot-$(date +%Y%m%d)"

# Restore snapshot
curl -X POST "http://elasticsearch:9200/_snapshot/cobalto/snapshot-20240101/_restore"
```

## Security

### Secrets Management

- **Development**: Environment variables in docker-compose.yml
- **Staging/Production**: HashiCorp Vault + Kubernetes Secrets

### Certificate Management

```bash
# Check certificates
kubectl get certificates -n production

# Renew certificates
kubectl delete secret cobalto-tls -n production
certbot renew
```

## Communication

### Deployment Notifications

1. **Slack**: #deployments channel
2. **Email**: soc-team@cobalto.io
3. **Status Page**: status.cobalto.io

### Incident Communication

1. **Internal**: #incidents channel
2. **External**: status.cobalto.io
3. **Customers**: Email notification