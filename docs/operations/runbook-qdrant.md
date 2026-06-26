# Qdrant Operations Runbook

## Overview

Qdrant is the vector database used for semantic search of threat intelligence, alert embeddings, and case similarity. This runbook covers collection management, embedding troubleshooting, and performance tuning.

## Quick Reference

| Item                | Value                              |
|---------------------|------------------------------------|
| Namespace           | `cobalto-data`                     |
| Deployment          | `qdrant`                           |
| Port                | 6333 (REST), 6334 (gRPC)          |
| Health Check        | `GET /healthz`                     |
| Dashboard           | `GET /dashboard`                   |
| Logs                | `kubectl logs -n cobalto-data deploy/qdrant` |
| Config              | `ConfigMap/qdrant-config`          |

## Common Issues

### Collection Creation Failures

**Diagnosis**:

```bash
# Check Qdrant health
kubectl exec -n cobalto-data deploy/qdrant -- curl -s localhost:6333/healthz

# List existing collections
kubectl exec -n cobalto-data deploy/qdrant -- curl -s localhost:6333/collections | jq '.result.collections[]'

# Check disk space
kubectl exec -n cobalto-data deploy/qdrant -- df -h /qdrant/storage

# Check Qdrant logs for errors
kubectl logs -n cobalto-data deploy/qdrant --tail=50 | grep -i "error\|fail"
```

**Fixes**:

```bash
# Create collection with correct dimensions
kubectl exec -n cobalto-data deploy/qdrant -- curl -X PUT localhost:6333/collections/threat-intel \
  -H "Content-Type: application/json" \
  -d '{
    "vectors": {
      "size": 1536,
      "distance": "Cosine"
    },
    "optimizers_config": {
      "default_segment_number": 2,
      "memmap_threshold": 20000
    }
  }'

# Increase storage if needed
kubectl patch pvc qdrant-storage -n cobalto-data -p '{"spec":{"resources":{"requests":{"storage":"50Gi"}}}}'
```

### Embedding Failures

**Symptoms**: Vector insertions failing, search returning empty results.

**Diagnosis**:

```bash
# Check embedding dimensions match collection
kubectl exec -n cobalto-data deploy/qdrant -- curl -s localhost:6333/collections/threat-intel | jq '.result.config.params.vectors.size'

# Test embedding API
curl -s http://langgraph-agent.cobalto-core:8080/api/embed -H "Content-Type: application/json" -d '{"text": "test"}' | jq '.embedding | length'

# Check Qdrant memory usage
kubectl top pods -n cobalto-data -l app=qdrant

# Verify collection point count
kubectl exec -n cobalto-data deploy/qdrant -- curl -s localhost:6333/collections/threat-intel | jq '.result.points_count'
```

**Fixes**:

```bash
# Recreate collection with correct dimensions (DESTRUCTIVE)
kubectl exec -n cobalto-data deploy/qdrant -- curl -X DELETE localhost:6333/collections/threat-intel
kubectl exec -n cobalto-data deploy/qdrant -- curl -X PUT localhost:6333/collections/threat-intel \
  -H "Content-Type: application/json" \
  -d '{"vectors": {"size": 1536, "distance": "Cosine"}}'
```

### Search Performance Issues

**Symptoms**: Semantic search queries slow, timeouts on large result sets.

**Diagnosis**:

```bash
# Benchmark search performance
time kubectl exec -n cobalto-data deploy/qdrant -- curl -s localhost:6333/collections/threat-intel/points/search \
  -H "Content-Type: application/json" \
  -d '{"vector": [0.1, 0.2, ...], "limit": 10}'

# Check segment count and optimization status
kubectl exec -n cobalto-data deploy/qdrant -- curl -s localhost:6333/collections/threat-intel | jq '.result.segments'

# Monitor search latency in Grafana
# Dashboard: Qdrant Operations > Search Latency
```

**Tuning**:

```bash
# Optimize collection (runs in background)
kubectl exec -n cobalto-data deploy/qdrant -- curl -X POST localhost:6333/collections/threat-intel/optimize

# Increase replicas for read scaling
kubectl exec -n cobalto-data deploy/qdrant -- curl -X PUT localhost:6333/collections/threat-intel \
  -H "Content-Type: application/json" \
  -d '{"replication": {"replication_factor": 2}}'

# Tune HNSW index parameters
kubectl exec -n cobalto-data deploy/qdrant -- curl -X PATCH localhost:6333/collections/threat-intel \
  -H "Content-Type: application/json" \
  -d '{"optimizer_config": {"memmap_threshold": 30000}}'
```

### Backup and Restore

```bash
# Create snapshot
kubectl exec -n cobalto-data deploy/qdrant -- curl -X POST localhost:6333/collections/threat-intel/snapshots

# Download snapshot
kubectl cp cobalto-data/$(kubectl get pod -n cobalto-data -l app=qdrant -o jsonpath='{.items[0].metadata.name}'):qdrant/storage/collections/threat-intel/snapshots/latest ./qdrant-backup-$(date +%Y%m%d).snapshot

# Restore from snapshot
kubectl cp ./qdrant-backup.snapshot cobalto-data/$(kubectl get pod -n cobalto-data -l app=qdrant -o jsonpath='{.items[0].metadata.name}'):/tmp/restore.snapshot
kubectl exec -n cobalto-data deploy/qdrant -- curl -X POST localhost:6333/collections/threat-intel/snapshots/upload -F "snapshot=@/tmp/restore.snapshot"
```

## Monitoring

| Metric                  | Alert Threshold | Severity |
|-------------------------|-----------------|----------|
| Point count growth      | > 1M/day        | Warning  |
| Memory usage            | > 80%           | Warning  |
| Search latency (p99)    | > 500ms         | Warning  |
| Search latency (p99)    | > 2s            | Critical |
| Disk usage              | > 75%           | Warning  |
| Disk usage              | > 90%           | Critical |
| Snapshot age            | > 24h           | Warning  |
