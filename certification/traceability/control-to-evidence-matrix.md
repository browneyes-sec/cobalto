# Control-to-Evidence Master Matrix

> Complete mapping of all certification controls to their evidence artifacts.  
> This is the single source of truth for auditor evidence requests.

## Conventions

- **Control ID format:** `{Domain}-{NN}` where Domain = PI (Pipeline Integrity), SP (Security Posture), RS (Resilience), PF (Performance), CM (Compliance), DG (Data Governance)
- **Status:** ✅ Certified, ⏳ Pending, ❌ Not Certified
- **Evidence path:** Relative to `certification/evidence/`

## Master Matrix

| Control ID | Domain | Description | Status | Evidence Artifact | Test Procedure | Frequency |
|-----------|--------|-------------|--------|-------------------|---------------|-----------|
| PI-01 | Pipeline Integrity | Input validation rejects malformed payloads | ✅ | `pipeline/validation-logs.json` | `security-controls-test.sh` | Every commit |
| PI-02 | Pipeline Integrity | Schema lock prevents extra fields | ✅ | `pipeline/schema-enforcement.json` | `security-controls-test.sh` | Every commit |
| PI-03 | Pipeline Integrity | Alert deduplication by alert_id | ⏳ | `pipeline/dedup-logs.json` | `pipeline-integrity-test.sh` | Pending |
| PI-04 | Pipeline Integrity | HMAC receipt for every tool call | ✅ | `pipeline/hmac-receipts.json` | `pipeline-integrity-test.sh` | Every commit |
| PI-05 | Pipeline Integrity | State machine preserves original alert | ✅ | `pipeline/state-integrity.json` | `pipeline-integrity-test.sh` | Every commit |
| PI-06 | Pipeline Integrity | Pipeline completes on known pathways | ✅ | `pipeline/pipeline-completions.json` | `pipeline-integrity-test.sh` | Every commit |
| PI-07 | Pipeline Integrity | Error paths produce logged failures | ✅ | `pipeline/error-logs.json` | `pipeline-integrity-test.sh` | Every commit |
| PI-08 | Pipeline Integrity | Alert ordering preserved within session | ⏳ | `pipeline/ordering-logs.json` | Pending | Pending |
| SP-01 | Security Posture | API key auth (HMAC constant-time) | ✅ | `security/auth-middleware.json` | `security-controls-test.sh` | Every commit |
| SP-02 | Security Posture | No-keys warning mode | ✅ | `security/no-keys-warning.json` | Manual | Per deployment |
| SP-03 | Security Posture | Console JWT auth (login/verify/refresh/logout) | ✅ | `security/console-auth.json` | `security-controls-test.sh` | Every commit |
| SP-04 | Security Posture | Bcrypt password hashing | ✅ | `security/bcrypt-config.json` | `security-controls-test.sh` | Per deploy |
| SP-05 | Security Posture | Token rotation on refresh | ✅ | `security/token-rotation.json` | `security-controls-test.sh` | Every commit |
| SP-06 | Security Posture | Rate limiting (token bucket) | ✅ | `security/rate-limiter.json` | `security-controls-test.sh` | Every commit |
| SP-07 | Security Posture | Audit log HMAC signing | ✅ | `security/audit-log.json` | `security-controls-test.sh` | Every commit |
| SP-08 | Security Posture | Input validation schema lock | ✅ | `security/schema-lock.json` | `security-controls-test.sh` | Every commit |
| SP-09 | Security Posture | Prompt injection detection | ✅ | `security/injection-guard.json` | `security-controls-test.sh` | Every commit |
| SP-10 | Security Posture | Vault dynamic secret rotation | ⏳ | `security/vault-rotation.json` | Manual | Weekly |
| SP-11 | Security Posture | Container securityContext enforcement | ✅ | `security/security-context.json` | CI k8s-hardening | Every commit |
| SP-12 | Security Posture | Network policy isolation | ✅ | `security/network-policies.json` | CI k8s-hardening | Every commit |
| RS-01 | Resilience | PodDisruptionBudget | ✅ | `resilience/pdb-config.json` | `resilience-test.sh` | Every commit |
| RS-02 | Resilience | Liveness probes | ✅ | `resilience/liveness-probes.json` | `resilience-test.sh` | Every commit |
| RS-03 | Resilience | Readiness probes | ✅ | `resilience/readiness-probes.json` | `resilience-test.sh` | Every commit |
| RS-04 | Resilience | Resource limits | ✅ | `resilience/resource-limits.json` | `resilience-test.sh` | Every commit |
| RS-05 | Resilience | Graceful dependency degradation | ✅ | `resilience/degradation-test.json` | `resilience-test.sh` | Weekly |
| RS-06 | Resilience | Retry logic for external API calls | ✅ | `resilience/retry-logs.json` | `resilience-test.sh` | Weekly |
| RS-07 | Resilience | Circuit breaker for cascading failures | ⏳ | `resilience/circuit-breaker.json` | Pending | Pending |
| RS-08 | Resilience | Pod anti-affinity | ✅ | `resilience/anti-affinity.json` | `resilience-test.sh` | Per deploy |
| RS-09 | Resilience | Graceful shutdown | ⏳ | `resilience/graceful-shutdown.json` | Pending | Pending |
| PF-01 | Performance | Alert ingestion latency SLA | ✅ | `performance/alert-ingestion.json` | `performance-benchmark.sh` | Weekly |
| PF-02 | Performance | Agent latency per severity | ✅ | `performance/agent-latency.json` | `performance-benchmark.sh` | Weekly |
| PF-03 | Performance | Auth service latency | ✅ | `performance/auth-latency.json` | `performance-benchmark.sh` | Weekly |
| PF-04 | Performance | Health endpoint responsiveness | ✅ | `performance/health-latency.json` | `performance-benchmark.sh` | Weekly |
| PF-05 | Performance | Regression detection | ✅ | `performance/baseline-comparison.json` | `compare_baseline.py` | Weekly |
| PF-06 | Performance | Resource utilization under load | ⏳ | `performance/resource-utilization.json` | Manual | Monthly |
| PF-07 | Performance | Throughput capacity | ⏳ | `performance/throughput-capacity.json` | Pending | Pending |
| CM-01 | Compliance | Continuous monitoring | ✅ | `compliance/monitoring-logs.json` | `compliance-evidence-test.sh` | Monthly |
| CM-02 | Compliance | Incident response procedures | ✅ | `compliance/incident-reports.json` | `compliance-evidence-test.sh` | Per incident |
| CM-03 | Compliance | Risk assessment | ✅ | `compliance/risk-assessment.json` | `compliance-evidence-test.sh` | Per alert |
| CM-04 | Compliance | Logical access controls | ✅ | `compliance/access-controls.json` | `compliance-evidence-test.sh` | Monthly |
| CM-05 | Compliance | Change management | ✅ | `compliance/change-management.json` | `compliance-evidence-test.sh` | Per deploy |
| CM-06 | Compliance | Threat detection | ✅ | `compliance/threat-detection.json` | `compliance-evidence-test.sh` | Continuous |
| CM-07 | Compliance | Incident response | ✅ | `compliance/incident-response.json` | `compliance-evidence-test.sh` | Per incident |
| CM-08 | Compliance | Automated audit trails | ✅ | `compliance/audit-trail.json` | `compliance-evidence-test.sh` | Continuous |
| CM-09 | Compliance | Audit trail retention | ✅ | `compliance/retention-config.json` | `compliance-evidence-test.sh` | Quarterly |
| CM-10 | Compliance | Security testing | ✅ | `compliance/security-tests.json` | `compliance-evidence-test.sh` | Weekly |
| CM-11 | Compliance | Security management process | ⏳ | `compliance/risk-management.json` | Pending | Pending |
| CM-12 | Compliance | Access control (HIPAA) | ✅ | `compliance/hipaa-access.json` | `compliance-evidence-test.sh` | Monthly |
| CM-13 | Compliance | Audit controls (HIPAA) | ✅ | `compliance/hipaa-audit.json` | `compliance-evidence-test.sh` | Continuous |
| CM-14 | Compliance | Integrity controls (HIPAA) | ✅ | `compliance/hipaa-integrity.json` | `compliance-evidence-test.sh` | Continuous |
| CM-15 | Compliance | Transmission security | ✅ | `compliance/tls-config.json` | `compliance-evidence-test.sh` | Quarterly |
| CM-16 | Compliance | Storage limitation (GDPR) | ✅ | `compliance/gdpr-retention.json` | `compliance-evidence-test.sh` | Quarterly |
| CM-17 | Compliance | Integrity + confidentiality (GDPR) | ✅ | `compliance/gdpr-integrity.json` | `compliance-evidence-test.sh` | Quarterly |
| DG-01 | Data Governance | TLS 1.3 / mTLS | ✅ | `governance/tls-config.json` | `compliance-evidence-test.sh` | Quarterly |
| DG-02 | Data Governance | AES-256 at rest | ✅ | `governance/encryption-config.json` | `compliance-evidence-test.sh` | Quarterly |
| DG-03 | Data Governance | Vault PKI certificates | ✅ | `governance/vault-pki.json` | Weekly | Per rotation |
| DG-04 | Data Governance | Vault dynamic secrets | ⏳ | `governance/vault-dynamic.json` | Monthly | Monthly |
| DG-05 | Data Governance | PII masking | ✅ | `governance/pii-masking.json` | `compliance-evidence-test.sh` | Weekly |
| DG-06 | Data Governance | Data retention policies | ✅ | `governance/retention-policies.json` | `compliance-evidence-test.sh` | Quarterly |
| DG-07 | Data Governance | Data deletion verification | ⏳ | `governance/deletion-verification.json` | Pending | Pending |
| DG-08 | Data Governance | Backup encryption + integrity | ✅ | `governance/backup-config.json` | Monthly | Monthly |
| DG-09 | Data Governance | Immutable audit log storage | ⏳ | `governance/immutable-storage.json` | Pending | Pending |

## Summary

| Domain | Total Controls | Certified | Pending | Not Certified | Coverage |
|--------|:-------------:|:---------:|:-------:|:-------------:|:--------:|
| Pipeline Integrity | 8 | 6 | 2 | 0 | 75% |
| Security Posture | 12 | 11 | 1 | 0 | 92% |
| Resilience | 9 | 7 | 2 | 0 | 78% |
| Performance | 7 | 5 | 2 | 0 | 71% |
| Compliance | 17 | 15 | 2 | 0 | 88% |
| Data Governance | 9 | 7 | 2 | 0 | 78% |
| **Total** | **62** | **51** | **11** | **0** | **82%** |

> **Target:** 100% certification coverage by Phase 5 (Audit Readiness).
