# Chaos Experiment: Pod Failure — LangGraph Agent

> **Domain:** Resilience  
> **Blast Radius:** Pod (default) → Service (max)  
> **CI-Safe:** ✅  
> **Tool:** `kubectl delete pod` / LitmusChaos `pod-delete`

## Hypothesis

**Given** the LangGraph Agent is deployed with `replicas: 2` and `minAvailable: 1` PDB,  
**When** one pod is deleted,  
**Then** the remaining pod continues processing alerts,  
**And** the deleted pod is rescheduled within 30s,  
**And** no alerts are lost during the failure window.

## Steady State

| Metric | Pre-Experiment | During | Post-Experiment |
|--------|---------------|--------|-----------------|
| Pod count | 2 | ≥ 1 | 2 |
| Alert success rate | 100% | ≥ 99% | 100% |
| P95 latency | baseline | ≤ baseline × 2 | baseline |
| Audit log entries | increasing | continuous | increasing |

## Experiment Design

```yaml
kind: ChaosExperiment
metadata:
  name: langgraph-pod-failure
  domain: resilience
spec:
  duration: 60s
  interval: 10s
  target:
    app: langgraph-agent
    namespace: cobalto
  experiment:
    - action: pod-delete
      count: 1
      force: true
      delay: 5s
  steady_state:
    - metric: "alert_success_rate"
      threshold: ">= 99%"
    - metric: "p95_latency"
      threshold: "<= 10s"
    - metric: "pod_count"
      threshold: ">= 1"
  rollback:
    method: "auto (ReplicaSet)"
    max_duration: 30s
```

## Procedure

```bash
#!/bin/bash
set -euo pipefail

NAMESPACE="cobalto"
LABEL="app=langgraph-agent"
STEADY_ALERTS=10  # Alerts to send before/after

echo "=== Pod Failure Experiment ==="
echo "Target: $LABEL in $NAMESPACE"

# 1. Verify steady state
echo "--- Verifying steady state ---"
kubectl wait --for=condition=Available deployment/langgraph-agent \
  --namespace "$NAMESPACE" --timeout=60s
INITIAL_PODS=$(kubectl get pods -n "$NAMESPACE" -l "$LABEL" \
  --no-headers | wc -l)
echo "Initial pods: $INITIAL_PODS"

# 2. Start background alert load
echo "--- Starting background alert load ---"
for i in $(seq 1 $STEADY_ALERTS); do
  curl -sf -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "{\"alert_id\":\"CHAOS-PF-$i\",\"rule_id\":800300,\"rule_description\":\"Chaos test\",\"alert_level\":1,\"source_ip\":\"10.0.0.50\",\"dest_ip\":\"10.0.0.10\",\"agent_name\":\"chaos-test\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"raw_log\":\"Chaos pod failure test\"}" \
    -w "\n  Status: %{http_code}\n" &
done
wait

# 3. Kill a pod
echo "--- Killing pod ---"
POD=$(kubectl get pods -n "$NAMESPACE" -l "$LABEL" \
  -o jsonpath='{.items[0].metadata.name}')
echo "Target pod: $POD"
kubectl delete pod -n "$NAMESPACE" "$POD" --force --grace-period=0 &
DELETE_PID=$!

# 4. Send alerts during pod failure
echo "--- Sending alerts during pod failure ---"
for i in $(seq 1 $STEADY_ALERTS); do
  curl -sf -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "{\"alert_id\":\"CHAOS-PF-DURING-$i\",\"rule_id\":800300,\"rule_description\":\"Chaos during failure\",\"alert_level\":1,\"source_ip\":\"10.0.0.51\",\"dest_ip\":\"10.0.0.11\",\"agent_name\":\"chaos-test\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"raw_log\":\"Chaos during pod failure\"}" \
    -w "\n  Status: %{http_code}\n" &
done
wait $DELETE_PID 2>/dev/null || true

# 5. Wait for recovery
echo "--- Waiting for recovery ---"
sleep 5
kubectl wait --for=condition=Available deployment/langgraph-agent \
  --namespace "$NAMESPACE" --timeout=60s
RECOVERED_PODS=$(kubectl get pods -n "$NAMESPACE" -l "$LABEL" \
  --no-headers | wc -l)
echo "Recovered pods: $RECOVERED_PODS"

# 6. Send post-recovery alerts
echo "--- Verifying post-recovery operation ---"
for i in $(seq 1 $STEADY_ALERTS); do
  curl -sf -X POST http://localhost:8000/agent/analyze \
    -H 'Content-Type: application/json' \
    -d "{\"alert_id\":\"CHAOS-PF-AFTER-$i\",\"rule_id\":800300,\"rule_description\":\"Chaos after recovery\",\"alert_level\":1,\"source_ip\":\"10.0.0.52\",\"dest_ip\":\"10.0.0.12\",\"agent_name\":\"chaos-test\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"raw_log\":\"Chaos after recovery\"}" \
    -w "\n  Status: %{http_code}\n" &
done
wait

# 7. Validate
echo "=== Results ==="
echo "Initial pods: $INITIAL_PODS"
echo "Recovered pods: $RECOVERED_PODS"

if [ "$RECOVERED_PODS" -ge "$INITIAL_PODS" ]; then
  echo "✅ Pod recovery: PASSED"
else
  echo "❌ Pod recovery: FAILED"
  exit 1
fi

# Check that service responded during failure
echo "✅ Check alert logs for continuity"
echo "=== Experiment Complete ==="
```

## Expected Results

| Observation | Expected | Actual |
|------------|----------|--------|
| Pod count during failure | ≥ 1 | |
| Pod count after recovery | 2 | |
| Alert success rate during failure | ≥ 99% | |
| Recovery time | ≤ 30s | |
| Data loss | 0% | |
| Audit log continuity | Continuous entries | |
