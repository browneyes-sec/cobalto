# Resilience Certification

> **Domain:** System survivability under component failures  
> **Control Owner:** DevOps / SRE  
> **Steady State:** Alert processing continues despite individual pod failures, network partitions, and dependency degradation

## Certification Scope

Certifies that the platform maintains functionality when components fail. Resilience is measured by the platform's ability to continue processing alerts, retain data, and recover without manual intervention.

| Failure Mode | Scope | Resilience Control |
|-------------|-------|-------------------|
| Pod crash | LangGraph Agent | K8s ReplicaSet + PDB (minAvailable: 1), liveness/readiness probes |
| Dependency failure | Qdrant / OpenCTI / ES timeout | Async tool calls with timeout, fallback status, enriched service degradation |
| Network partition | Service-to-service connectivity | Istio mTLS with retry, circuit breaker, NetworkPolicy isolation |
| Node failure | K8s worker node | PodDisruptionBudget, anti-affinity, multi-AZ (production) |
| Resource exhaustion | Memory / CPU / disk | Resource limits, HorizontalPodAutoscaler, OOM-kill recovery |
| API throttling | External API rate limits | Exponential backoff, degraded enrichment fallback |
| Secret expiry | Vault dynamic secret TTL | Vault agent sidecar auto-renewal, pre-expiry rotation |

## Steady State Definition

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Alert success rate under pod failure | ≥ 99% of alerts processed during pod rollout | Chaos experiment |
| Recovery time after pod failure | ≤ 30s (liveness check interval × failure threshold) | `kubectl rollout status` |
| Dependency degradation handling | 100% of API timeouts produce graceful degradation | Integration test |
| Data durability under node failure | 0% data loss | PDB + replica count validation |
| Resource limit enforcement | 0% OOM-killed pods exceed memory limit | Prometheus metric check |
| Secret rotation continuity | 0% authentication failures during rotation | Vault test |

## Controls Under Certification

| Control ID | Control | Evidence | Test Procedure |
|-----------|---------|----------|---------------|
| RS-01 | PodDisruptionBudget (minAvailable ≥ 1) | PDB manifest existence + validation | K8s hardening CI |
| RS-02 | Liveness probe (HTTP GET /health) | Probe config in deployment | K8s manifest scan |
| RS-03 | Readiness probe (HTTP GET /ready) | Probe config in deployment | K8s manifest scan |
| RS-04 | Resource limits (CPU + memory) | limits configured on all containers | K8s manifest scan |
| RS-05 | Graceful dependency degradation | Integration test with mocked failures | `resilience-test.sh` |
| RS-06 | Retry logic for external API calls | Integration test with transient failures | `resilience-test.sh` |
| RS-07 | Circuit breaker for cascading failures | Fallback behavior on critical dependency | Chaos experiment |
| RS-08 | Pod anti-affinity (production) | Affinity rules in deployment | K8s manifest scan |
| RS-09 | Graceful shutdown (SIGTERM handling) | PreStop hook, connection draining | Chaos experiment |

## Chaos Experiments

| Experiment | Hypothesis | Blast Radius |
|-----------|-----------|-------------|
| [Pod failure](../../chaos/experiments/pod-failure.md) | Killing 1 langgraph-agent pod: remaining pods process alerts without data loss | Pod |
| [Network partition](../../chaos/experiments/network-partition.md) | Cutting Qdrant connectivity: alerts processed with degraded enrichment | Service |
| [API degradation](../../chaos/experiments/api-degradation.md) | External API timeouts ≥ 5s: pipeline returns enrichment_failed status, alert preserved | Service |
| [Load spike](../../chaos/experiments/load-spike.md) | 10× normal alert rate: no crashes, rate limiting enforces backpressure | Service |
| Node failure (staging only) | K8s worker node drain: pods rescheduled, no data loss | Cluster |

## Test Coverage Requirements

- **Integration tests:** All external dependencies mocked for timeout/failure scenarios
- **E2E tests:** Full pipeline test with degraded dependencies
- **K8s validation:** PDB, probe, resource limit checks on every deployment/statefulset
- **Chaos experiments:** Each experiment runs at least once before L2 certification

## Certification Procedure

```bash
# 1. Validate K8s resilience configuration
bash scripts/validate-hardening.sh

# 2. Run resilience integration tests
PYTHONPATH=services/langgraph-agent python3 -m pytest \
  tests/integration/test_api.py -k "failure or error or timeout" -v

# 3. Run pod failure chaos experiment
./certification/procedures/resilience-test.sh --experiment pod-failure

# 4. Run network partition chaos experiment
./certification/procedures/resilience-test.sh --experiment network-partition

# 5. Generate evidence
python3 certification/evidence/generate-package.py --domain resilience
```

## Current Status

| Control | L1 (CI Gate) | L2 (Validation) | L3 (Evidence) | L4 (Audit) |
|---------|:-------------:|:----------------:|:--------------:|:-----------:|
| RS-01 | ✅ 8 PDBs created | ✅ Validated | ⏳ Template ready | ⏳ Planned |
| RS-02 | ✅ All deployments | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| RS-03 | ✅ All deployments | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| RS-04 | ✅ 15 workloads | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| RS-05 | ✅ 3 failure tests | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| RS-06 | ✅ 3 integration tests | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| RS-07 | ⏳ No circuit breaker impl | ⏳ Pending | ⏳ Pending | ⏳ Planned |
| RS-08 | ✅ Production manifests | ✅ Validated | ⏳ Template ready | ⏳ Planned |
| RS-09 | ⏳ Not implemented | ⏳ Pending | ⏳ Pending | ⏳ Planned |
