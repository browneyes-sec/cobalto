# Performance Certification

> **Domain:** Latency, throughput, and capacity under production-equivalent load  
> **Control Owner:** Platform Engineer  
> **Steady State:** Alert processing p95 < 5s, auth p95 < 500ms, health p95 < 100ms, zero errors under sustained 20 VUs

## Certification Scope

Certifies that the platform meets performance SLAs under defined load profiles. Performance baselines are maintained in `tests/benchmark/baselines/` and enforced via CI.

| Workload | Benchmark Test | SLA Target |
|----------|---------------|-----------|
| Alert ingestion (LOW severity) | `alert_ingestion.js` (20 VUs) | p95 < 5s, p99 < 10s, fail < 1% |
| Alert ingestion (MEDIUM severity) | `agent_latency.js` (5 VUs steady) | p95 < 10s, p99 < 15s |
| Console auth login | `auth_burst.js` (50 concurrent) | p95 < 500ms, p99 < 1s |
| Health/readiness probes | `health_check.js` (100 concurrent) | p95 < 100ms, fail < 0.1% |
| Token verification | `auth_burst.js` | p95 < 200ms |
| Token refresh | `auth_burst.js` | p95 < 300ms |

## Steady State Definition

| Metric | Threshold | Test Source |
|--------|-----------|-------------|
| Alert ingestion p50 | < 1.2s baseline | `alert_ingestion.js` |
| Alert ingestion p95 | < 5.0s baseline | `alert_ingestion.js` |
| Alert ingestion p99 | < 10.0s baseline | `alert_ingestion.js` |
| Alert ingestion failure rate | < 1% | `alert_ingestion.js` |
| Agent latency p50 (LOW) | < 2.0s baseline | `agent_latency.js` |
| Agent latency p95 (LOW) | < 5.0s baseline | `agent_latency.js` |
| Agent latency p50 (MEDIUM) | < 3.0s baseline | `agent_latency.js` |
| Auth login p95 | < 500ms baseline | `auth_burst.js` |
| Auth login p99 | < 1s baseline | `auth_burst.js` |
| Auth login failure rate | < 5% (429 expected) | `auth_burst.js` |
| Health check p95 | < 100ms baseline | `health_check.js` |
| Readiness check p95 | < 100ms baseline | `health_check.js` |
| Metrics endpoint p95 | < 200ms baseline | `health_check.js` |
| Health check failure rate | < 0.1% | `health_check.js` |

## Controls Under Certification

| Control ID | Control | Evidence | Test Procedure |
|-----------|---------|----------|---------------|
| PF-01 | Alert ingestion latency SLA | k6 benchmark results | `performance-benchmark.sh` |
| PF-02 | Agent latency per severity | k6 custom metrics | `performance-benchmark.sh` |
| PF-03 | Auth service latency | k6 auth burst results | `performance-benchmark.sh` |
| PF-04 | Health endpoint responsiveness | k6 health check results | `performance-benchmark.sh` |
| PF-05 | Regression detection (20% tolerance) | Baseline comparison script | `compare_baseline.py` |
| PF-06 | Resource utilization under load | Prometheus metrics + k6 correlation | Manual review |
| PF-07 | Throughput capacity (max VUs without failure) | Progressive load test | Custom experiment |

## Chaos Experiments

| Experiment | Hypothesis | Blast Radius |
|-----------|-----------|-------------|
| [Load spike](../../chaos/experiments/load-spike.md) | 10× normal rate: p95 may degrade but pipeline does not crash | Service |
| Resource exhaustion | Memory limit reached: OOM-killed pod restarts without data loss | Pod |

## Baseline Management

Baselines are stored in `tests/benchmark/baselines/v1.json` with the following management rules:

- **Creation:** Initial baseline established during Phase 3-3 setup
- **Update:** Run with `--baseline` flag after intentional performance changes
- **CI enforcement:** `performance-benchmark` job compares current vs. cached baseline
- **Regression threshold:** 20% p95 increase = CI failure
- **Warning threshold:** 15% p95 increase = warning in PR comment

## Test Coverage Requirements

- **k6 tests:** All 4 test scripts run on push to `main` (label `perf` for PRs)
- **Coverage per endpoint:** Each API endpoint has at least one benchmark test
- **Duration:** Minimum 30s steady-state per test phase
- **VU profiles:** Include warm-up, peak, and cool-down stages

## Certification Procedure

```bash
# 1. Run all benchmarks
make bench-ci

# 2. Verify against baseline
python3 tests/benchmark/compare_baseline.py \
  --baseline tests/benchmark/baselines/v1.json \
  --results-dir tests/benchmark/reports/ \
  --timestamp $(date +%Y%m%dT%H%M%S)

# 3. Generate performance report
python3 certification/evidence/generate-package.py --domain performance
```

## Current Status

| Control | L1 (CI Gate) | L2 (Validation) | L3 (Evidence) | L4 (Audit) |
|---------|:-------------:|:----------------:|:--------------:|:-----------:|
| PF-01 | ✅ 4 k6 tests | ✅ CI job | ⏳ Template ready | ⏳ Planned |
| PF-02 | ✅ 2 severity levels | ✅ CI job | ⏳ Template ready | ⏳ Planned |
| PF-03 | ✅ 50-VU burst | ✅ CI job | ⏳ Template ready | ⏳ Planned |
| PF-04 | ✅ 100-VU concurrent | ✅ CI job | ⏳ Template ready | ⏳ Planned |
| PF-05 | ✅ 20% threshold | ✅ `compare_baseline.py` | ✅ Automated | ⏳ Planned |
| PF-06 | ⏳ Not integrated | ⏳ Pending | ⏳ Pending | ⏳ Planned |
| PF-07 | ⏳ Not implemented | ⏳ Pending | ⏳ Pending | ⏳ Planned |

## Known Baseline Values

Initial baselines from CI-kind environment (single-node, CPU-only inference):

| Metric | Baseline | Tolerance | Notes |
|--------|----------|-----------|-------|
| Alert ingestion p50 | 1.2s | ±20% | CPU-only LLM inference |
| Alert ingestion p95 | 4.5s | ±20% | Expect improvement with GPU |
| Auth login p95 | 300ms | ±25% | bcrypt rounds=4 in CI |
| Health check p95 | 30ms | ±30% | Minimal overhead expected |
