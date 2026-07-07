# Chaos Experiment: Load Spike — 10× Normal Alert Ingestion

> **Domain:** Performance  
> **Blast Radius:** Service (default) → Namespace (max)  
> **CI-Safe:** ✅  
> **Tool:** k6 + rate limiter integration tests

## Hypothesis

**Given** the LangGraph Agent is configured with rate limiting at 60 requests/minute per agent,  
**When** the alert submission rate spikes to 10× the normal rate (600 req/min sustained for 30s),  
**Then** the rate limiter returns HTTP 429 for excess requests,  
**And** the service remains responsive (no crashes, no OOM),  
**And** P95 latency stays below 10s for accepted requests,  
**And** no false 5xx errors occur.

## Steady State

| Metric | Pre-Experiment | During | Post-Experiment |
|--------|---------------|--------|-----------------|
| Throughput | normal baseline | rate-limited to configured RPM | normal baseline |
| P95 latency | baseline | ≤ 10s | baseline |
| HTTP 429 rate | 0% | ~88% (at 10× over limit) | 0% |
| HTTP 5xx rate | 0% | 0% | 0% |
| Memory utilization | ≤ 60% | ≤ 85% | ≤ 60% |
| Pod health | Running | Running | Running |

## Experiment Design

```yaml
kind: ChaosExperiment
metadata:
  name: load-spike-alert-ingestion
  domain: performance
spec:
  duration: 60s
  interval: 5s
  target:
    app: langgraph-agent
    namespace: cobalto
  experiment:
    - action: load-spike
      traffic_type: alert_ingestion
      target_rpm: 600  # 10× normal
      duration: 30s
      ramp_up: 10s
      ramp_down: 10s
  steady_state:
    - metric: "http_5xx_rate"
      threshold: "= 0%"
    - metric: "memory_utilization"
      threshold: "<= 85%"
    - metric: "service_health"
      threshold: "always healthy"
  rollback:
    method: "automatic rate limiting absorbs excess"
    max_duration: 10s
```

## Procedure

```bash
#!/bin/bash
set -euo pipefail

echo "=== Load Spike Experiment: 10× Alert Ingestion ==="

BASE_URL="${COBALTO_BENCHMARK_URL:-http://localhost:8000}"
NORMAL_RPM=60
SPIKE_RPM=600
DURATION="30s"

# 1. Verify steady state
echo "--- Verifying steady state ---"
curl -sf "$BASE_URL/health" || {
  echo "ERROR: Service not reachable"
  exit 1
}
echo "Service healthy"

# 2. Run normal load for baseline
echo "--- Running normal load (${NORMAL_RPM} req/min) ---"
k6 run --vus 1 --duration 10s \
  -e COBALTO_BENCHMARK_URL="$BASE_URL" \
  tests/benchmark/health_check.js \
  --summary-export=/tmp/chaos-baseline.json 2>&1 | tail -3

# 3. Run spike load
echo "--- Running SPIKE load (${SPIKE_RPM} req/min) ---"
k6 run \
  --vus 10 \
  --duration "$DURATION" \
  --stage "0s: 5, 10s: 10, 20s: 10, 25s: 5" \
  -e COBALTO_BENCHMARK_URL="$BASE_URL" \
  - <<'K6SCRIPT' 2>&1 | tee /tmp/chaos-spike-results.log
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const errors = new Rate('chaos_spike_errors');
const rateLimited = new Rate('chaos_spike_rate_limited');
const latency = new Trend('chaos_spike_latency');

export default function () {
  const alertId = `CHAOS-SPIKE-${__VU}-${__ITER}`;
  const payload = JSON.stringify({
    alert_id: alertId,
    rule_id: 800300,
    rule_description: 'Chaos load spike test',
    alert_level: 1,
    source_ip: '10.0.0.90',
    dest_ip: '10.0.0.50',
    agent_name: 'chaos-spike',
    timestamp: new Date().toISOString(),
    raw_log: 'Chaos load spike test',
  });

  const res = http.post(
    __ENV.COBALTO_BENCHMARK_URL + '/agent/analyze',
    payload,
    { headers: { 'Content-Type': 'application/json' } }
  );

  latency.add(res.timings.duration);

  if (res.status === 429) {
    rateLimited.add(true);
  } else if (res.status !== 200) {
    errors.add(true);
    console.error(`ERROR: ${res.status} for ${alertId}`);
  } else {
    check(res, {
      'has incident_id': (r) => JSON.parse(r.body).incident_id !== '',
    });
  }

  // Minimal think time to generate high load
  sleep(0.05);
}
K6SCRIPT

# 4. Verify recovery
echo "--- Verifying recovery ---"
sleep 5
curl -sf "$BASE_URL/health" || {
  echo "ERROR: Service did not recover from spike"
  exit 1
}
echo "Service recovered"

# 5. Run health check to verify steady state restored
echo "--- Verifying steady state restored ---"
k6 run --vus 1 --duration 10s \
  -e COBALTO_BENCHMARK_URL="$BASE_URL" \
  tests/benchmark/health_check.js \
  --summary-export=/tmp/chaos-recovery.json 2>&1 | tail -3

# 6. Parse results
echo ""
echo "=== Spike Results ==="
SPIKE_429=$(grep -oP 'chaos_spike_rate_limited.*?(\d+\.\d+)' /tmp/chaos-spike-results.log | tail -1 || echo "N/A")
SPIKE_5XX=$(grep -oP 'chaos_spike_errors.*?(\d+\.\d+)' /tmp/chaos-spike-results.log | tail -1 || echo "N/A")

echo "Rate limited (429): $SPIKE_429 (expected: ~88%)"
echo "Errors (5xx): $SPIKE_5XX (expected: 0%)"

if echo "$SPIKE_5XX" | grep -q "0"; then
  echo "✅ No 5xx errors during spike"
else
  echo "❌ 5xx errors detected during spike!"
fi

echo "=== Load Spike Experiment Complete ==="
```

## Expected Results

| Observation | Expected | Actual |
|------------|----------|--------|
| Rate-limited requests (429) | ~88% of spike traffic | |
| 5xx errors | 0% | |
| Service health during spike | healthy (Running) | |
| P95 latency for accepted reqs | < 10s | |
| Memory utilization | < 85% | |
| Recovery time | < 10s | |
| Post-spike health | baseline restored | |
