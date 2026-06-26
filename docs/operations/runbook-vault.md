# Vault Operations Runbook

## Overview

HashiCorp Vault manages all secrets, PKI certificates, and dynamic credentials for the Cobalto platform. This runbook covers unsealing, secret management, certificate operations, and disaster recovery.

## Quick Reference

| Item                | Value                              |
|---------------------|------------------------------------|
| Namespace           | `cobalto-system`                   |
| Deployment          | `vault`                            |
| Port                | 8200 (API), 8201 (cluster)        |
| Health Check        | `GET /v1/sys/health`               |
| Logs                | `kubectl logs -n cobalto-system deploy/vault` |
| UI                  | `https://vault.<domain>`           |

## Common Issues

### Vault is Sealed

**Symptoms**: Services failing to retrieve secrets, `Vault is sealed` errors.

**Diagnosis**:

```bash
# Check Vault status
kubectl exec -n cobalto-system deploy/vault -- vault status

# Check seal status via API
kubectl exec -n cobalto-system deploy/vault -- curl -s localhost:8200/v1/sys/seal-status | jq '.sealed, .t, .n'
```

**Unseal Procedure**:

```bash
# Method 1: Auto-unseal with KMS (preferred)
# Vault should auto-unseal if configured with AWS KMS. Check logs for errors.

# Method 2: Manual unseal (emergency)
# Requires 3 of 5 unseal keys
kubectl exec -n cobalto-system deploy/vault -it -- vault operator unseal <key-1>
kubectl exec -n cobalto-system deploy/vault -it -- vault operator unseal <key-2>
kubectl exec -n cobalto-system deploy/vault -it -- vault operator unseal <key-3>

# Verify unseal
kubectl exec -n cobalto-system deploy/vault -- vault status | jq '.sealed'
```

### Secret Rotation Failures

**Symptoms**: Services reporting expired credentials, database connection failures.

**Diagnosis**:

```bash
# Check database secret engine
kubectl exec -n cobalto-system deploy/vault -- vault read database/creds/langgraph-role

# Check lease count
kubectl exec -n cobalto-system deploy/vault -- vault lease list | grep database

# Check Vault logs for rotation errors
kubectl logs -n cobalto-system deploy/vault | grep -i "rotate\|revoke\|expire"

# Test dynamic credential generation
kubectl exec -n cobalto-system deploy/vault -- vault read database/creds/test-role
```

**Fix**:

```bash
# Force rotate static credential
kubectl exec -n cobalto-system deploy/vault -- vault write database/rotate-role/langgraph-role

# Revoke expired leases
kubectl exec -n cobalto-system deploy/vault -- vault lease revoke database/creds/langgraph-role/<lease-id>

# Restart affected service to pick up new credentials
kubectl rollout restart deployment/langgraph-agent -n cobalto-core
```

### PKI Certificate Renewal

**Symptoms**: mTLS handshake failures between services, certificate expired errors.

**Diagnosis**:

```bash
# Check intermediate CA expiry
kubectl exec -n cobalto-system deploy/vault -- vault read pca/issuance/ca | jq '.data.certificate'

# List issued certificates
kubectl exec -n cobalto-system deploy/vault -- vault list pca/issuance/cert/<serial>

# Check certificate expiry from service
kubectl exec -n cobalto-core deploy/langgraph-agent -- openssl s_client -connect qdrant.cobalto-data:6333 -showcerts 2>/dev/null | openssl x509 -noout -dates
```

**Fix**:

```bash
# Rotate intermediate CA (if near expiry)
kubectl exec -n cobalto-system deploy/vault -- vault write pca/issuance/roles/intermediate ca_ttl=8760h

# Revoke and reissue certificate for a service
kubectl exec -n cobalto-system deploy/vault -- vault write pca/issuance/cert/<serial> ttl=86400

# Force all services to re-fetch certificates
kubectl rollout restart deployment/langgraph-agent -n cobalto-core
kubectl rollout restart deployment/n8n -n cobalto-core
kubectl rollout restart deployment/thehive -n cobalto-intel
```

### Audit Log Management

**Diagnosis**:

```bash
# Check audit backend status
kubectl exec -n cobalto-system deploy/vault -- vault audit list -detailed

# Check audit log size
kubectl exec -n cobalto-system deploy/vault -- wc -l /vault/audit/audit.log

# Search audit log for specific access
kubectl exec -n cobalto-system deploy/vault -- grep '"auth/token/create"' /vault/audit/audit.log | tail -20

# Check for denied requests
kubectl exec -n cobalto-system deploy/vault -- grep '"error":"permission denied"' /vault/audit/audit.log | tail -20
```

**Management**:

```bash
# Rotate audit log
kubectl exec -n cobalto-system deploy/vault -- mv /vault/audit/audit.log /vault/audit/audit-$(date +%Y%m%d).log
kubectl exec -n cobalto-system deploy/vault -- kill -HUP 1  # Signal to reopen log file

# Archive old audit logs to S3
kubectl exec -n cobalto-system deploy/vault -- aws s3 cp /vault/audit/audit-$(date -d "7 days ago" +%Y%m%d).log s3://cobalto-audit-logs/vault/
```

### Service Authentication Issues

**Symptoms**: Pods unable to authenticate to Vault, `permission denied` errors.

**Diagnosis**:

```bash
# Check Kubernetes auth backend
kubectl exec -n cobalto-system deploy/vault -- vault auth list | grep kubernetes

# Check role bindings
kubectl exec -n cobalto-system deploy/vault -- vault read auth/kubernetes/role/langgraph-agent

# Verify service account token
kubectl exec -n cobalto-core deploy/langgraph-agent -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d | jq '.kubernetes.io.serviceaccount.name, .kubernetes.io.serviceaccount.namespace'
```

**Fix**:

```bash
# Re-create Kubernetes auth role
kubectl exec -n cobalto-system deploy/vault -- vault write auth/kubernetes/role/langgraph-agent \
  bound_service_account_names=langgraph-agent \
  bound_service_account_namespaces=cobalto-core \
  policies=langgraph-policy \
  ttl=1h

# Reload Kubernetes auth config
kubectl exec -n cobalto-system deploy/vault -- vault write auth/kubernetes/config kubernetes_host="https://kubernetes.default.svc"
```

## Backup and Restore

```bash
# Create snapshot (Raft backend)
kubectl exec -n cobalto-system deploy/vault -- vault operator raft snapshot save /tmp/vault-snapshot-$(date +%Y%m%d).snap

# Download snapshot
kubectl cp cobalto-system/$(kubectl get pod -n cobalto-system -l app=vault -o jsonpath='{.items[0].metadata.name}'):/tmp/vault-snapshot.snap ./vault-snapshot-$(date +%Y%m%d).snap

# Restore snapshot (on recovery node)
kubectl exec -n cobalto-system deploy/vault -it -- vault operator raft snapshot restore /tmp/restore.snap
```

## Disaster Recovery

```bash
# Step 1: Seal Vault (prevent writes)
kubectl exec -n cobalto-system deploy/vault -- vault operator seal

# Step 2: Restore snapshot on primary node
kubectl cp ./vault-snapshot.snap cobalto-system/$(kubectl get pod -n cobalto-system -l app=vault -o jsonpath='{.items[0].metadata.name}'):/tmp/restore.snap
kubectl exec -n cobalto-system deploy/vault -it -- vault operator raft snapshot restore /tmp/restore.snap

# Step 3: Unseal and promote
kubectl exec -n cobalto-system deploy/vault -it -- vault operator unseal <key-1>
kubectl exec -n cobalto-system deploy/vault -it -- vault operator unseal <key-2>
kubectl exec -n cobalto-system deploy/vault -it -- vault operator unseal <key-3>
kubectl exec -n cobalto-system deploy/vault -- vault operator raft peer-promote <node-id>
```

## Monitoring

| Metric                  | Alert Threshold | Severity |
|-------------------------|-----------------|----------|
| Vault sealed            | true            | Critical |
| Active client count     | > 500           | Warning  |
| Token count             | > 10000         | Warning  |
| Lease count             | > 5000          | Warning  |
| Audit log size          | > 1GB           | Warning  |
| Certificate expiry      | < 7 days        | Warning  |
| Certificate expiry      | < 24 hours      | Critical |
| Request latency (p99)   | > 1s            | Warning  |
