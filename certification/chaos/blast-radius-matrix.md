# Blast Radius Matrix

> Governs experiment progression: start at pod scope, escalate only after lower-level controls pass.  
> **Principle:** Never run a namespace-level experiment before all pod-level experiments pass.

## Risk Classification

| Scope | Risk Level | Approval | Examples |
|-------|-----------|----------|---------|
| **Pod** | Low | Self-service (Chaos Engineer) | Kill single pod, restart container |
| **Service** | Medium | Certification Engineer + Control Owner | Network partition, dependency degradation |
| **Namespace** | High | Certification Authority + Internal Auditor | Node drain, multiple service degradation |
| **Cluster** | Critical | Certification Authority + CISO | Region failure, full network partition |

## Experiment Progression Rules

```
Pod-Level (all pass)
    ↓
Service-Level (all pass)
    ↓
Namespace-Level (all pass)
    ↓
Cluster-Level (rare, only in staging)
```

If any experiment at a given level fails, all higher-level experiments are blocked until the failure is remediated and the lower-level experiment re-passes.

## Blast Radius by Experiment

| Experiment | Default Scope | Max Scope | CI-Safe | Staging Only | Risk Mitigation |
|-----------|--------------|-----------|---------|-------------|----------------|
| Pod failure — LangGraph Agent | Pod | Service | ✅ | — | PDB minAvailable prevents total outage |
| Pod failure — console-auth | Pod | Service | ✅ | — | Graceful degradation, retry logic |
| Network partition — Qdrant | Service | Namespace | ✅ | — | Enrichment_failed fallback |
| Network partition — Vault | Service | Namespace | — | ✅ | Critical secrets impact |
| API degradation — OpenCTI | Service | Service | ✅ | — | Timeout fallback tested |
| API degradation — all external | Service | Namespace | — | ✅ | Dependency cascade risk |
| Secret rotation — Vault PKI | Namespace | Namespace | ✅ | — | Auto-renewal, grace period |
| Secret rotation — dynamic DB | Namespace | Namespace | — | ✅ | Connection pool drain risk |
| Load spike — 10× alerts | Service | Namespace | ✅ | — | Rate limiting absorbs burst |
| Load spike — 100× alerts | Service | Namespace | — | ✅ | Resource exhaustion risk |
| Data corruption — malformed alert | Pod | Pod | ✅ | — | Schema validation rejects |
| Data corruption — queue poison | Pod | Service | ⏳ Pending | — | Requires dead-letter queue |
| Node failure | Namespace | Cluster | — | ✅ | Entire workload migration |
| Key material corruption | Service | Namespace | — | ✅ | Manual recovery required |

## CI Execution Rules

### For `performance-benchmark` CI job
- **Allowed:** All pod-level experiments, service-level experiments with `CI-Safe: ✅`
- **Blocked:** Any experiment with `CI-Safe: —`
- **Blast radius protection:** kind cluster is ephemeral (destroyed after CI run)
- **Safety limit:** Maximum 3 concurrent experiments per CI run
- **Duration limit:** Each experiment ≤ 60s

### For Weekly Chaos Day (scheduled)
- **Allowed:** Pod-level + service-level + namespace-level with approval
- **Environment:** Dedicated staging cluster (not CI)
- **Blast radius protection:** Staging cluster isolated from production
- **Safety limit:** Maximum 1 namespace-level experiment per chaos day
- **Duration limit:** Each experiment ≤ 300s

## Rollback Procedures

Every experiment must have a documented rollback procedure tested before execution.

| Experiment | Rollback Method | Max Rollback Time |
|-----------|----------------|-------------------|
| Pod failure | K8s ReplicaSet auto-recovery | 30s (liveness probe) |
| Network partition | NetworkPolicy / Istio config restore | 10s |
| API degradation | Service mesh traffic routing restore | 10s |
| Secret rotation | Vault secret restore from version history | 30s |
| Load spike | k6 ramp-down in test options | 5s (automatic) |
| Data corruption | Pod restart clears in-memory state | 30s |
| Node failure | New node joins cluster (auto-scaling) | 300s |
| Key material corruption | KMS key version rollback | 60s |

## Experiment Feedback Loop

```
Experiment Result
    ↓
┌─── PASS ───→ Update confidence score → Escalate to next level
│
└─── FAIL ───→ Log regression → Block higher-level experiments
                    ↓
           Create certification finding
                    ↓
           Assign to Control Owner
                    ↓
           Remediate → Re-test → Re-certify
```
