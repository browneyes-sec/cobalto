# Resilience Domain — Controls RS-01 through RS-10

**Steady-State Hypothesis**: The platform continues to serve alerts within degraded SLOs during partial failures and recovers fully within 60s of failure resolution.

## Controls

| ID | Control | Verification | Procedure |
|----|---------|-------------|-----------|
| RS-01 | Pod failure — single agent restarts | Agent responds after `docker restart` | chaos-pod-failure.sh |
| RS-02 | Pod failure — no data loss on restart | Alert count persists across restart | chaos-pod-failure.sh |
| RS-03 | Network partition — agent recovers after isolation | Agent responds after network restore | chaos-network-partition.sh |
| RS-04 | Dependency failure — graceful degradation | Agent returns degraded response when Qdrant is down | chaos-dependency-failure.sh |
| RS-05 | Dependency failure — recovery after restore | Full functionality after dependency comes back | chaos-dependency-failure.sh |
| RS-06 | Resource exhaustion — OOM prevention | Process handles memory pressure without crash | resource-exhaustion.sh |
| RS-07 | Startup — clean initialization | Service starts without errors after restart | startup-test.sh |
| RS-08 | Startup — dependency ordering | Service waits for postgres/redis before accepting traffic | startup-test.sh |
| RS-09 | Long-running — no memory leak | Memory stable over 100+ alert cycles | endurance-test.sh |
| RS-10 | Long-running — no metric leak | Metric cardinality stable over 100+ alert cycles | endurance-test.sh |

## Steady-State Verification
- Service is running and responding to health checks
- Baseline metrics captured before experiment
- Recovery verified after experiment
