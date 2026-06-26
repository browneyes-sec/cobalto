# Elasticsearch Operations Runbook

## Overview

Elasticsearch stores alert data, case metadata, logs, and observables for TheHive and OpenCTI. This runbook covers cluster management, index lifecycle, and performance tuning.

## Quick Reference

| Item                | Value                              |
|---------------------|------------------------------------|
| Namespace           | `cobalto-data`                     |
| StatefulSet         | `elasticsearch`                    |
| Port                | 9200 (REST), 9300 (transport)     |
| Health Check        | `GET /_cluster/health`             |
| Logs                | `kubectl logs -n cobalto-data statefulset/elasticsearch` |
| Config              | `ConfigMap/elasticsearch-config`   |

## Common Issues

### Cluster Health RED

**Symptoms**: `/_cluster/health` returns `"status": "red"`, data loss or indexing failures.

**Diagnosis**:

```bash
# Check cluster health
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cluster/health?pretty

# Find unassigned shards
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/shards?v&h=index,shard,prirep,state,unassigned.reason | grep UNASSIGNED

# Check node availability
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/nodes?v&h=name,heap.percent,ram.percent,disk.avail,node.role

# Check for failed allocations
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cluster/allocation/explain?pretty
```

**Fixes**:

```bash
# Reroute unassigned primary shards
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X POST localhost:9200/_cluster/reroute -H "Content-Type: application/json" -d '{"commands":[{"allocate_stale_primary":{"index":"<index>","shard":0,"node":"<node>","accept_data_loss":true}}]}'

# Increase watermark to allow shard allocation on nearly-full disks
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X PUT localhost:9200/_cluster/settings -H "Content-Type: application/json" -d '{"transient":{"cluster.routing.allocation.disk.watermark.low":"90%","cluster.routing.allocation.disk.watermark.high":"95%","cluster.routing.allocation.disk.watermark.flood_stage":"97%"}}'

# Restart failed node
kubectl rollout restart statefulset/elasticsearch -n cobalto-data
```

### Cluster Health YELLOW

**Symptoms**: Primary shards allocated, replica shards unassigned.

**Diagnosis**:

```bash
# Check replica shard status
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/shards?v&h=index,shard,prirep,state | grep UNASSIGNED

# Check disk space on nodes
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/allocation?v

# Check for under-replicated indices
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/indices?v&health=yellow
```

**Fix**:

```bash
# Force allocate replicas
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X POST localhost:9200/_cluster/reroute -H "Content-Type: application/json" -d '{"commands":[{"allocate_replica":{"index":"<index>","shard":0,"node":"<node>"}}]}'
```

### Index Management

```bash
# List all indices with size
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/indices?v&s=store.size:desc

# Check ILM policy status
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_ilm/explain | jq '.indices | to_entries[] | select(.value.step_info.error)'

# Force ILM step
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X POST localhost:9200/_ilm/move/<index> -H "Content-Type: application/json" -d '{"current_step":{"phase":"hot","action":"rollover","name":"check-rollover-ready"},"next_step":{"phase":"warm","action":"shrink","name":"shrink"}}'

# Delete old indices (free space)
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X DELETE localhost:9200/logs-cobalto-*

# Close cold indices to save memory
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X POST localhost:9200/<old-index>/_close
```

### Shard Allocation Issues

**Diagnosis**:

```bash
# Check shard allocation explanation
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cluster/allocation/explain -H "Content-Type: application/json" -d '{"index":"<index>","shard":0,"primary":true}'

# Check disk-based allocation settings
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cluster/settings?pretty | grep -A5 "watermark"

# Check rebalancing status
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_cat/recovery?v&active_only=true
```

**Fix**:

```bash
# Disable allocation during maintenance
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X PUT localhost:9200/_cluster/settings -H "Content-Type: application/json" -d '{"transient":{"cluster.routing.allocation.enable":"primaries"}}'

# Re-enable after maintenance
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X PUT localhost:9200/_cluster/settings -H "Content-Type: application/json" -d '{"transient":{"cluster.routing.allocation.enable":"all"}}'
```

### Performance Tuning

```bash
# Check hot threads
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_nodes/hot_threads?threads=5

# Check slow query logs
kubectl logs -n cobalto-data statefulset/elasticsearch | grep "slow query"

# Monitor indexing rate
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_nodes/stats/indices/indexing | jq '.nodes[].indices.indexing.index_total'
```

**Tuning Checklist**:

| Setting                         | Recommended Value              | Location              |
|---------------------------------|--------------------------------|-----------------------|
| `ES_JAVA_OPTS`                  | `-Xms4g -Xmx4g`               | StatefulSet env       |
| `cluster.routing.allocation.disk.watermark.low` | `85%` | Cluster settings |
| `indices.memory.index_buffer_size` | `20%`                      | elasticsearch.yml     |
| `index.translog.flush_threshold_size` | `1gb`                   | Index settings        |

## Backup and Restore

```bash
# Register snapshot repository
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X PUT localhost:9200/_snapshot/cobalto-backup -H "Content-Type: application/json" -d '{
  "type": "fs",
  "settings": {
    "location": "/backup/elasticsearch",
    "compress": true
  }
}'

# Create snapshot
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X PUT localhost:9200/_snapshot/cobalto-backup/snapshot-$(date +%Y%m%d)?wait_for_completion=true

# List snapshots
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -s localhost:9200/_snapshot/cobalto-backup/_all | jq '.snapshots[] | {snapshot, state, start_time}'

# Restore snapshot
kubectl exec -n cobalto-data statefulset/elasticsearch -- curl -X POST localhost:9200/_snapshot/cobalto-backup/<snapshot>/_restore -H "Content-Type: application/json" -d '{"indices": "<index>"}'
```

## Monitoring

| Metric                  | Alert Threshold | Severity |
|-------------------------|-----------------|----------|
| Cluster health          | RED             | Critical |
| Cluster health          | YELLOW > 30min  | Warning  |
| JVM heap usage          | > 75%           | Warning  |
| JVM heap usage          | > 85%           | Critical |
| Disk usage              | > 80%           | Warning  |
| Unassigned shards       | > 0             | Warning  |
| Indexing rate drop      | > 50%           | Warning  |
| Search latency (p99)    | > 2s            | Warning  |
