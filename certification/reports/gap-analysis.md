# Certification Gap Analysis

**Generated**: 2026-07-07T17:18:40Z
**Environment**: dev
**Total Controls**: 62
**Controls Tested**: 49
**Controls with Gaps**: 8

---

## Gap Summary

| # | Control | Title | Severity | Tested? |
|---|---------|-------|----------|---------|
| 1 | SC-08 | HMAC Audit Secret Mismatch | **HIGH** | ✅ |
| 2 | OB-06 | No Alerting Rules Configured | **CRITICAL** | ❌ |
| 3 | RS-04/RS-05 | No Circuit Breaker for External Dependencies | **HIGH** | ✅ |
| 4 | SC-01/SC-02 | Authentication Disabled in Development | **MEDIUM** | ✅ |
| 5 | SC-10 | Prompt Injection Guard Bypass | **MEDIUM** | ✅ |
| 6 | SC-12/SC-13 | Kubernetes Security Context Not Enforced | **MEDIUM** | ❌ |
| 7 | PE-04/PE-05/PE-06 | Tool Latency Metrics Require Instrumented Tools | **MEDIUM** | ✅ |
| 8 | CM-03 | No Backup or Disaster Recovery Procedures | **CRITICAL** | ✅ |

---

## Detailed Findings

### 1. [HIGH] HMAC Audit Secret Mismatch (SC-08)

**Observation**: Audit trail HMAC signatures cannot be verified with the documented default secret ("change-me-in-production"). Either the secret was changed or the signing process has a serialization mismatch.

**Control was testable**: Yes — evidence artifact generated

**Recommended Remediation**: Document the correct HMAC secret in deployment configs. Add HMAC verification to CI/CD pipeline. Consider using Vault for secret distribution.

---
### 2. [CRITICAL] No Alerting Rules Configured (OB-06)

**Observation**: Prometheus has no rule_files configured. Platform emits all metrics but cannot fire alerts on threshold breaches.

**Control was testable**: No — requires implementation before testing

**Recommended Remediation**: Define 6 alerting rules (agent error rate, tool latency, alert ingestion stall, LLM budget, queue depth, pod CPU). Add Alertmanager with Slack notification routing.

---
### 3. [HIGH] No Circuit Breaker for External Dependencies (RS-04/RS-05)

**Observation**: Agent calls OpenCTI, TheHive, Cortex, Qdrant without circuit breaker pattern. A failing dependency cascades into agent failures.

**Control was testable**: Yes — evidence artifact generated

**Recommended Remediation**: Implement circuit breaker wrapper with three states (closed/open/half-open). Default to degraded rule-based triage when external services are unavailable.

---
### 4. [MEDIUM] Authentication Disabled in Development (SC-01/SC-02)

**Observation**: COBALTO_DISABLE_AUTH allows unauthenticated API access. Acceptable for dev but must be enforced in staging/production.

**Control was testable**: Yes — evidence artifact generated

**Recommended Remediation**: Ensure CI/CD enforces COBALTO_API_KEY in staging/production environments.

---
### 5. [MEDIUM] Prompt Injection Guard Bypass (SC-10)

**Observation**: Standard injection payload ("Ignore previous instructions") passed through as HTTP 200. Guard relies on regex patterns that may miss LLM-specific injection variants.

**Control was testable**: Yes — evidence artifact generated

**Recommended Remediation**: Implement XML input wrapping, add more injection patterns, consider ML-based detection for prompt injection.

---
### 6. [MEDIUM] Kubernetes Security Context Not Enforced (SC-12/SC-13)

**Observation**: Helm templates lack runAsNonRoot, readOnlyRootFilesystem, and capabilities.drop settings.

**Control was testable**: No — requires implementation before testing

**Recommended Remediation**: Add securityContext to all pod specs in Helm chart templates. Verify with kube-bench in CI.

---
### 7. [MEDIUM] Tool Latency Metrics Require Instrumented Tools (PE-04/PE-05/PE-06)

**Observation**: Tool latency histogram exists but only 3 tools are instrumented with @metrics.instrument_tool(). Tool latency benchmarks not meaningful.

**Control was testable**: Yes — evidence artifact generated

**Recommended Remediation**: Instrument all external tool calls with the decorator. Add baseline measurements for each tool.

---
### 8. [CRITICAL] No Backup or Disaster Recovery Procedures (CM-03)

**Observation**: PostgreSQL (state), Redis (cache), Qdrant (embeddings) have no backup mechanism. No DR runbooks exist.

**Control was testable**: Yes — evidence artifact generated

**Recommended Remediation**: Implement Velero for PVC snapshots, pg_dump cron for Postgres, Qdrant snapshot API to S3. Document recovery runbooks.

---

## Controls Not Testable

- **OB-06**: No Alerting Rules Configured — Define 6 alerting rules (agent error rate, tool latency, alert ingestion stall, LLM budget, queue depth, pod CPU). Add Alertmanager with Slack notification routing.
- **SC-12/SC-13**: Kubernetes Security Context Not Enforced — Add securityContext to all pod specs in Helm chart templates. Verify with kube-bench in CI.
