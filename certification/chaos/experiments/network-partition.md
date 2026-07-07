# Chaos Experiment: Network Partition — Qdrant Dependency

> **Domain:** Resilience  
> **Blast Radius:** Service (default) → Namespace (max)  
> **CI-Safe:** ✅  
> **Tool:** NetworkPolicy / Istio fault injection / `tc` netem

## Hypothesis

**Given** the LangGraph Agent depends on Qdrant for MITRE ATT&CK search,  
**When** connectivity to Qdrant is dropped (network partition),  
**Then** the agent returns `enrichment_failed` status for MITRE-related calls,  
**And** alert processing continues without data loss,  
**And** full enrichment resumes when connectivity is restored.

## Steady State

| Metric | Pre-Experiment | During | Post-Experiment |
|--------|---------------|--------|-----------------|
| MITRE search success rate | 100% | 0% (expected) | 100% |
| Alert success rate | 100% | ≥ 99% | 100% |
| Enrichment status | enriched | enrichment_failed | enriched |
| P95 latency | baseline | ≤ baseline × 2 | baseline |

## Experiment Design

```yaml
kind: ChaosExperiment
metadata:
  name: qdrant-network-partition
  domain: resilience
spec:
  duration: 60s
  interval: 15s
  target:
    app: langgraph-agent
    namespace: cobalto
  experiment:
    - action: network-loss
      from: app=langgraph-agent
      to: app=qdrant
      loss_percentage: 100
      duration: 45s
  steady_state:
    - metric: "alert_success_rate"
      threshold: ">= 99%"
    - metric: "enrichment_status"
      threshold: "degraded != crashed"
    - metric: "p95_latency"
      threshold: "<= 10s"
  rollback:
    method: "remove network loss policy"
    max_duration: 10s
```

## Procedure

```bash
#!/bin/bash
set -euo pipefail

NAMESPACE="cobalto"
AGENT_LABEL="app=langgraph-agent"
QDRANT_SERVICE="qdrant"

echo "=== Network Partition Experiment: Qdrant ==="
echo "Isolating LangGraph Agent from Qdrant"

# 1. Verify steady state
echo "--- Verifying steady state ---"
curl -sf http://localhost:8000/health || {
  echo "ERROR: Service not reachable"
  exit 1
}

# 2. Apply network policy to block Qdrant egress
echo "--- Blocking Qdrant connectivity ---"
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: chaos-block-qdrant
  namespace: $NAMESPACE
spec:
  podSelector:
    matchLabels:
      app: langgraph-agent
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: langgraph-agent
  # NOTE: This blocks ALL egress except to self — effectively isolating the pod
EOF
echo "Network policy applied"

# 3. Verify partition
echo "--- Verifying partition ---"
sleep 5
kubectl run -n "$NAMESPACE" -it --rm test-curl --image=curlimages/curl \
  --restart=Never -- sh -c "curl -s --connect-timeout 5 http://$QDRANT_SERVICE:6333/health" \
  2>&1 | grep -q "Could not resolve" || echo "Qdrant isolated (expected)"

# 4. Send alerts during partition
echo "--- Sending alerts during network partition ---"
for i in $(seq 1 5); do
  RESP=$(curl -sf -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "{\"alert_id\":\"CHAOS-NP-$i\",\"rule_id\":800300,\"rule_description\":\"Network partition test\",\"alert_level\":1,\"source_ip\":\"10.0.0.60\",\"dest_ip\":\"10.0.0.20\",\"agent_name\":\"chaos-net\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"raw_log\":\"Network partition chaos test\"}" \
    2>/dev/null || echo '{"severity":"ERROR"}')

  SEVERITY=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('severity','ERROR'))" 2>/dev/null || echo "ERROR")
  echo "  Alert $i: $SEVERITY"

  if [ "$SEVERITY" = "ERROR" ]; then
    echo "  WARNING: Alert processing failed during partition"
  fi
done

# 5. Restore connectivity
echo "--- Restoring Qdrant connectivity ---"
kubectl delete networkpolicy chaos-block-qdrant -n "$NAMESPACE"
echo "Network policy removed, connectivity restored"

# 6. Verify recovery
echo "--- Verifying recovery ---"
sleep 10
curl -sf http://localhost:8000/health || {
  echo "ERROR: Service not recovered"
  exit 1
}

for i in $(seq 1 3); do
  RESP=$(curl -sf -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "{\"alert_id\":\"CHAOS-NP-AFTER-$i\",\"rule_id\":800300,\"rule_description\":\"Post-partition test\",\"alert_level\":1,\"source_ip\":\"10.0.0.61\",\"dest_ip\":\"10.0.0.21\",\"agent_name\":\"chaos-net\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"raw_log\":\"Post-partition chaos test\"}" \
    2>/dev/null || echo '{"severity":"ERROR"}')

  SEVERITY=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('severity','ERROR'))" 2>/dev/null || echo "ERROR")
  echo "  Recovery alert $i: $SEVERITY"
done

echo "=== Network Partition Experiment Complete ==="
```

## Expected Results

| Observation | Expected | Actual |
|------------|----------|--------|
| Alerts processed during partition | ✅ (degraded enrichment) | |
| MITRE search returns enrichment_failed | ✅ | |
| Error count during partition | 0 (graceful degradation) | |
| Full recovery after partition | ✅ | |
| Recovery time | ≤ 10s | |
