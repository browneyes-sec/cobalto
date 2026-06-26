# Operations Runbook: LangGraph Agent Service

## Agent Service Debugging

### Service Health

```bash
# Check pod status
kubectl get pods -n langgraph -l app.kubernetes.io/name=langgraph-agent-service

# View logs
kubectl logs -n langgraph -l app.kubernetes.io/name=langgraph-agent-service --tail=100 -f

# Port-forward for local debugging
kubectl port-forward -n langgraph svc/langgraph-agent-service 8000:8000
```

### Health endpoints

```bash
# Liveness check
curl http://localhost:8000/health

# Readiness check
curl http://localhost:8000/ready

# Visualize agent graph
curl http://localhost:8000/graph/visualize | jq .mermaid
```

### Common Issues

#### Agent returning 500 errors

1. Check downstream service connectivity:
   - Qdrant: `curl http://qdrant.qdrant.svc.cluster.local:6333/healthz`
   - OpenCTI: `curl http://opencti.opencti.svc.cluster.local:4000/graphql`
   - Cortex: `curl http://cortex.cortex.svc.cluster.local:9001/api/v1/status`
2. Check secrets: `kubectl get secrets -n langgraph langgraph-secrets -o yaml`
3. Review agent logs for stack traces

#### Slow response times

1. Check pod resource usage: `kubectl top pods -n langgraph`
2. Verify HPA scaling: `kubectl get hpa -n langgraph`
3. Check for external service timeouts in logs
4. Review Qdrant query latency: `curl http://qdrant.qdrant.svc.cluster.local:6333/collections/mitre_attack`

#### Agent stuck / no response

1. Check thread count: look for "thread_id" in recent logs
2. Restart deployment: `kubectl rollout restart deployment/langgraph-agent-service -n langgraph`
3. Check memory usage and OOM kills: `kubectl describe pod -n langgraph <pod-name>`

## Performance Tuning

### Resource limits

Current production settings:
- Requests: 4Gi memory, 2000m CPU
- Limits: 8Gi memory, 4000m CPU

Adjust based on load testing results.

### HPA configuration

```yaml
minReplicas: 3
maxReplicas: 10
metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Connection pooling

For Qdrant client, reuse connections:
```python
# Reuse single client instance across requests
qdrant_client = QdrantClient(url=QDRANT_URL)
```

### Async operations

All external service calls (Qdrant, OpenCTI, Cortex) use `httpx.AsyncClient` for non-blocking I/O.

## Cost Monitoring

### OpenAI API costs

Monitor token usage per alert analysis:
- Track `usage.total_tokens` in OpenAI API responses
- Set budget alerts in OpenAI dashboard
- Cache frequently-used MITRE lookups in Qdrant to reduce embedding calls

### Infrastructure costs

- **Compute**: Track CPU/memory usage via Grafana dashboards
- **Storage**: Monitor Qdrant vector storage growth
- **Network**: Track inter-service traffic between pods

### Cost optimization strategies

1. **Embedding caching**: Store pre-computed embeddings for static MITRE data
2. **Batch processing**: Group similar alerts for batch analysis
3. **Response caching**: Cache enrichment results for repeated IOCs
4. **Right-sizing**: Use Vertical Pod Autoscaler recommendations

### Alerting thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU utilization | >70% | >90% |
| Memory utilization | >80% | >95% |
| Response time (p99) | >5s | >15s |
| Error rate | >1% | >5% |
| OpenAI daily spend | >$50 | >$200 |
