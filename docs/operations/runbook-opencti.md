# OpenCTI Operations Runbook

## Overview

OpenCTI is the threat intelligence platform managing STIX/TAXII data, connectors, and intelligence reports. This runbook covers connector management, query troubleshooting, and scaling.

## Quick Reference

| Item                | Value                              |
|---------------------|------------------------------------|
| Namespace           | `cobalto-intel`                    |
| Deployment          | `opencti`                          |
| Port                | 4000 (GraphQL), 4002 (Playground)  |
| Health Check        | `GET /health`                      |
| Logs                | `kubectl logs -n cobalto-intel deploy/opencti` |
| Config              | `Secret/opencti-config`            |
| Connectors          | Separate deployments in same namespace |

## Common Issues

### Connector Sync Failures

**Symptoms**: Connector pods showing errors or not syncing data.

**Diagnosis**:

```bash
# Check connector pod status
kubectl get pods -n cobalto-intel -l app=opencti-connector

# Check connector logs
kubectl logs -n cobalto-intel deploy/opencti-connector-misp --tail=100 | grep -i "error\|fail\|timeout"

# List active connectors via GraphQL
curl -s http://opencti.cobalto-intel:4000/graphql -H "Content-Type: application/json" -d '{"query":"query { connectors { id name active } }"}' | jq '.data.connectors[] | select(.active == true)'

# Check last sync timestamp
curl -s http://opencti.cobalto-intel:4000/graphql -H "Content-Type: application/json" -d '{"query":"query { workerConfig { last_update } }"}' | jq
```

**Common Fixes**:

| Issue                        | Fix                                                  |
|------------------------------|------------------------------------------------------|
| API key expired              | Rotate in Vault: `vault kv put secret/cobalto/opencti/misp-key value="new-key"` |
| Connector config error       | Update ConfigMap and restart connector pod           |
| Rate limiting                | Reduce polling interval in connector config          |
| STIX bundle malformed        | Validate with `stix2-validator` and check source     |

### GraphQL Query Timeouts

**Symptoms**: API queries timing out, dashboards failing to load.

**Diagnosis**:

```bash
# Check OpenCTI response times
kubectl logs -n cobalto-intel deploy/opencti | grep -i "slow\|timeout"

# Check Elasticsearch health (OpenCTI backend)
kubectl exec -n cobalto-data deploy/elasticsearch -c elasticsearch -- curl -s localhost:9200/_cluster/health | jq '.status, .unassigned_shards'

# Check memory usage
kubectl top pods -n cobalto-intel -l app=opencti

# Run query with timing
time curl -s http://opencti.cobalto-intel:4000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query":"query { indicators(first: 100) { edges { node { id value } } } }"}'
```

**Fixes**:

```bash
# Increase OpenCTI memory limits
kubectl patch deployment opencti -n cobalto-intel -p '{"spec":{"template":{"spec":{"containers":[{"name":"opencti","resources":{"requests":{"memory":"4Gi"},"limits":{"memory":"8Gi"}}}]}}}}'

# Increase Elasticsearch heap if needed
kubectl patch statefulset elasticsearch -n cobalto-data -p '{"spec":{"template":{"spec":{"containers":[{"name":"elasticsearch","env":[{"name":"ES_JAVA_OPTS","value":"-Xms4g -Xmx4g"}]}]}}}}'

# Clear OpenCTI cache (if Redis-backed)
kubectl exec -n cobalto-data deploy/redis -c redis -- redis-cli FLUSHDB
```

### STIX Import Errors

**Symptoms**: STIX bundles failing to import, data missing from platform.

**Diagnosis**:

```bash
# Validate STIX bundle
cat bundle.json | python3 -m stix2 validator

# Check import logs
kubectl logs -n cobalto-intel deploy/opencti | grep -i "stix\|import\|parse"

# Check for duplicate objects
curl -s http://opencti.cobalto-intel:4000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"query":"query { stixCoreObjects(first: 1) { edges { node { id } } } }"}' | jq
```

**Fix**:

```bash
# Import with force flag (overwrites existing)
curl -X POST http://opencti.cobalto-intel:4000/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@bundle.json" \
  -F "file_import=true" \
  -F "forceReplace=true"
```

### Worker Scaling

```bash
# Check current worker replicas
kubectl get deployments -n cobalto-intel -l role=worker

# Scale workers based on queue depth
kubectl scale deployment opencti-worker -n cobalto-intel --replicas=5

# Monitor worker processing rate
kubectl logs -n cobalto-intel deploy/opencti-worker --tail=50 | grep -c "processed"
```

## Backup and Restore

```bash
# Backup OpenCTI data (PostgreSQL)
kubectl exec -n cobalto-data deploy/postgresql -c postgresql -- pg_dump -U opencti opencti > opencti-backup-$(date +%Y%m%d).sql

# Backup Redis (session data)
kubectl exec -n cobalto-data deploy/redis -c redis -- redis-cli BGSAVE

# Restore PostgreSQL
cat opencti-backup-YYYYMMDD.sql | kubectl exec -i -n cobalto-data deploy/postgresql -c postgresql -- psql -U opencti opencti
```

## Monitoring

| Metric                  | Alert Threshold | Severity |
|-------------------------|-----------------|----------|
| Connector sync delay    | > 30min         | Warning  |
| Connector sync delay    | > 2h            | Critical |
| GraphQL response time   | > 5s            | Warning  |
| GraphQL response time   | > 30s           | Critical |
| Worker queue depth      | > 1000          | Warning  |
| Worker queue depth      | > 5000          | Critical |
| Memory usage            | > 80%           | Warning  |
