# n8n Operations Runbook

## Overview

n8n is the workflow automation platform handling webhook ingestion, alert triage routing, and notification delivery. This runbook covers troubleshooting, performance tuning, and scaling procedures.

## Quick Reference

| Item                | Value                              |
|---------------------|------------------------------------|
| Namespace           | `cobalto-core`                     |
| Deployment          | `n8n`                              |
| Port                | 5678                               |
| Health Check        | `GET /healthz`                     |
| Logs                | `kubectl logs -n cobalto-core deploy/n8n` |
| Config              | `ConfigMap/n8n-config`             |
| Credentials         | Vault KV `secret/cobalto/n8n/`     |

## Common Issues

### Workflow Not Triggering

**Symptoms**: Webhooks sent to n8n are not triggering workflows.

**Diagnosis**:

```bash
# Check if n8n pod is running
kubectl get pods -n cobalto-core -l app=n8n

# Check n8n logs for webhook errors
kubectl logs -n cobalto-core deploy/n8n --tail=100 | grep -i "webhook\|trigger"

# Verify webhook URL is correct
curl -X POST https://<n8n-url>/webhook/<workflow-id> -H "Content-Type: application/json" -d '{"test": true}'

# Check active workflows via API
curl -s https://<n8n-url>/api/v1/workflows -H "X-N8N-API-KEY: <key>" | jq '.data[] | {id, name, active}'
```

**Common Causes**:

| Cause                              | Fix                                              |
|-------------------------------------|--------------------------------------------------|
| Workflow is deactivated             | Activate via UI or API: `PATCH /api/v1/workflows/{id} {"active": true}` |
| Webhook URL changed                 | Update source system (Wazuh, Slack) with new URL |
| Execution queue stuck               | Restart n8n pod                                  |
| Credential expired                  | Rotate in Vault and update n8n credential store  |

### Webhook Returns 4xx/5xx

**Diagnosis**:

```bash
# Check n8n execution errors
kubectl logs -n cobalto-core deploy/n8n | grep -i "error\|500\|400"

# Check if webhook authentication is required
curl -v -X POST https://<n8n-url>/webhook/<id> -H "Content-Type: application/json" -d '{}'

# Review n8n execution history via API
curl -s https://<n8n-url>/api/v1/executions?limit=10 -H "X-N8N-API-KEY: <key>" | jq '.data[] | {id, status, finished}'
```

**Fixes**:

```bash
# Restart n8n to clear stuck state
kubectl rollout restart deployment/n8n -n cobalto-core

# Scale up if queue is backed up
kubectl scale deployment/n8n -n cobalto-core --replicas=3
```

### Credential Issues

**Symptoms**: Workflows fail with authentication errors when calling external services.

**Diagnosis**:

```bash
# Check Vault secret validity
vault kv get secret/cobalto/n8n/thehive-api-key

# Verify n8n can reach Vault
kubectl exec -n cobalto-core deploy/n8n -- curl -s http://vault.cobalto-system:8200/v1/sys/health

# Check credential expiry
vault kv get -version=latest secret/cobalto/n8n/slack-token | jq '.data.data | keys'
```

**Fix**:

```bash
# Rotate credential in Vault
vault kv put secret/cobalto/n8n/thehive-api-key value="new-api-key-here"

# Restart n8n to pick up new credentials
kubectl rollout restart deployment/n8n -n cobalto-core
```

### Performance Tuning

**Symptoms**: Workflows executing slowly, execution queue backing up.

**Diagnosis**:

```bash
# Check pod resource usage
kubectl top pods -n cobalto-core -l app=n8n

# Check execution metrics in Grafana
# Dashboard: n8n Operations > Execution Latency

# Review slow executions
curl -s "https://<n8n-url>/api/v1/executions?limit=20&status=error" -H "X-N8N-API-KEY: <key>" | jq '.data[] | {id, startedAt, stoppedAt, workflowId}'
```

**Tuning Steps**:

| Parameter              | Default    | Recommended  | Location                      |
|------------------------|------------|--------------|-------------------------------|
| `EXECUTIONS_PROCESS`   | `main`     | `fork`       | ConfigMap `n8n-config`        |
| `EXECUTIONS_DATA_PRUNE`| `false`    | `true`       | ConfigMap `n8n-config`        |
| `EXECUTIONS_DATA_MAX_AGE` | `0`     | `168` (7d)   | ConfigMap `n8n-config`        |
| `N8N_CONCURRENCY`      | `10`       | `25`         | ConfigMap `n8n-config`        |

### Scaling

```bash
# Horizontal scaling (stateless workers)
kubectl scale deployment/n8n -n cobalto-core --replicas=5

# Check HPA status
kubectl get hpa -n cobalto-core

# Vertical scaling (update resource limits)
kubectl patch deployment n8n -n cobalto-core -p '{"spec":{"template":{"spec":{"containers":[{"name":"n8n","resources":{"requests":{"cpu":"1000m","memory":"2Gi"},"limits":{"cpu":"2000m","memory":"4Gi"}}}]}}}}'
```

## Backup and Restore

```bash
# Backup n8n data (SQLite or PostgreSQL)
kubectl exec -n cobalto-core deploy/n8n -- n8n export:workflow --all --output=/tmp/backup.json
kubectl cp cobalto-core/$(kubectl get pod -n cobalto-core -l app=n8n -o jsonpath='{.items[0].metadata.name}'):/tmp/backup.json ./n8n-backup-$(date +%Y%m%d).json

# Restore workflows
kubectl cp ./n8n-backup.json cobalto-core/$(kubectl get pod -n cobalto-core -l app=n8n -o jsonpath='{.items[0].metadata.name}'):/tmp/restore.json
kubectl exec -n cobalto-core deploy/n8n -- n8n import:workflow --input=/tmp/restore.json
```

## Monitoring

| Metric                  | Alert Threshold | Severity |
|-------------------------|-----------------|----------|
| Execution failure rate  | > 5%            | Warning  |
| Queue depth             | > 100           | Warning  |
| Queue depth             | > 500           | Critical |
| Memory usage            | > 80%           | Warning  |
| Pod restarts            | > 3 in 10min    | Critical |
