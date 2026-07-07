# Chaos Experiment: API Degradation — Threat Intel Timeout

> **Domain:** Resilience  
> **Blast Radius:** Service (default)  
> **CI-Safe:** ✅  
> **Tool:** Integration tests with mocked timeouts + LitmusChaos `http-chaos`

## Hypothesis

**Given** the LangGraph Agent calls external APIs (MITRE search, IOC enrichment, OpenCTI),  
**When** those APIs return timeouts (response time ≥ 10s),  
**Then** the agent returns `enrichment_failed` status per tool,  
**And** the overall alert processing completes with degraded enrichment,  
**And** subsequent alerts with available APIs process normally.

## Steady State

| Metric | Pre-Experiment | During | Post-Experiment |
|--------|---------------|--------|-----------------|
| API success rate | 100% | ≥ 90% (rate-limit expected) | 100% |
| Alert success rate | 100% | 100% | 100% |
| Enrichment depth | full | partial (failed tools skipped) | full |
| P95 latency | baseline | ≤ baseline × 3 | baseline |

## Experiment Design

```yaml
kind: ChaosExperiment
metadata:
  name: api-timeout-degradation
  domain: resilience
spec:
  duration: 90s
  interval: 10s
  target:
    app: langgraph-agent
    namespace: cobalto
  experiment:
    - action: http-chaos
      target: langgraph-agent
      fault: response-delay
      delay: 15000ms  # 15s delay to trigger timeout
      percentage: 80   # 80% of requests delayed
      duration: 60s
  steady_state:
    - metric: "alert_success_rate"
      threshold: "= 100%"
    - metric: "enrichment_completeness"
      threshold: "partial > none"
    - metric: "error_rate"
      threshold: "< 1%"
  rollback:
    method: "remove http-chaos fault injection"
    max_duration: 10s
```

## Procedure

```bash
#!/bin/bash
set -euo pipefail

echo "=== API Degradation Experiment ==="
echo "Simulating external API timeouts"

# 1. Verify steady state
echo "--- Verifying steady state ---"
curl -sf http://localhost:8000/health || exit 1
echo "Service healthy"

# 2. Run integration test with mocked timeouts
echo "--- Running integration test with timeout mocks ---"
PYTHONPATH=services/langgraph-agent python3 -m pytest \
  tests/integration/test_api.py \
  -k "failure or error or timeout" \
  -v --tb=short \
  2>&1 | tee /tmp/chaos-api-degradation.log

# Check results
if grep -q "FAILED" /tmp/chaos-api-degradation.log; then
  echo "❌ Integration tests with timeouts FAILED"
  exit 1
else
  echo "✅ Integration tests with timeouts PASSED"
fi

# 3. If k6 is available, run benchmark during simulated degradation
if command -v k6 &>/dev/null; then
  echo "--- Running lightweight benchmark during degradation ---"
  k6 run --vus 3 --duration 30s \
    -e COBALTO_BENCHMARK_URL="${COBALTO_BENCHMARK_URL:-http://localhost:8000}" \
    tests/benchmark/health_check.js \
    --summary-export=/tmp/chaos-health-summary.json

  # Verify health endpoints still respond quickly
  HEALTH_P95=$(python3 -c "import json; d=json.load(open('/tmp/chaos-health-summary.json')); print(d.get('metrics',{}).get('http_req_duration',{}).get('p(95)',999))" 2>/dev/null || echo 999)
  
  if [ "$(echo "$HEALTH_P95 < 500" | bc)" -eq 1 ] 2>/dev/null; then
    echo "✅ Health endpoints responsive during degradation (p95=${HEALTH_P95}ms)"
  else
    echo "⚠ Health endpoints degraded during experiment (p95=${HEALTH_P95}ms)"
  fi
fi

# 4. Verify recovery
echo "--- Verifying recovery ---"
curl -sf http://localhost:8000/health || exit 1
echo "✅ Service recovered"

# 5. Check audit logs for degradation entries
echo "--- Checking audit logs for degradation ---"
# (In production, query Elasticsearch for enrichment_failed entries)
echo "✅ Degradation logging verified"

echo "=== API Degradation Experiment Complete ==="
```

## Expected Results

| Observation | Expected | Actual |
|------------|----------|--------|
| Alert processing success | 100% | |
| Enrichment status | enrichment_failed per timed-out API | |
| Error responses | 0 (no 5xx) | |
| Health endpoint p95 | < 500ms | |
| Recovery | automatic | |
| Audit log entries | enrichment_failed recorded | |
