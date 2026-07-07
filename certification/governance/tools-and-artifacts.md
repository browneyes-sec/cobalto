# Tools & Artifacts

> Authoritative toolchain for certification activities.

## Tool Inventory

| Tool | Version | Purpose | Certification Phase | Source |
|------|---------|---------|-------------------|--------|
| **k6** | ≥ 0.55 | Performance benchmarks (latency, throughput, auth burst) | Performance certification | `tests/benchmark/` |
| **LitmusChaos** | ≥ 3.0 | Chaos experiment orchestration on Kubernetes | Resilience certification | Helm chart |
| **kube-bench** | ≥ 0.9 | CIS Kubernetes benchmark validation | Technology certification | `kubernetes/security/kube-bench/` |
| **OPA/Gatekeeper** | ≥ 3.16 | Policy-as-code constraint enforcement | Security posture certification | `kubernetes/security/gatekeeper/` |
| **Trivy** | ≥ 0.49 | Container vulnerability scanning | Supply chain certification | CI pipeline |
| **k6 Operator** | ≥ 0.2 | Distributed load testing in K8s | Performance certification | Helm chart (planned) |
| **OpenSSL** | ≥ 3.0 | Certificate chain validation, HMAC verification | Data governance certification | System package |
| **Vault CLI** | ≥ 1.17 | Secrets lifecycle verification | Security posture certification | HashiCorp |

## Artifact Specifications

### Certification Evidence Artifact

```json
{
  "artifact_id": "uuid-v4",
  "domain": "pipeline-integrity | security-posture | resilience | performance | compliance | data-governance",
  "control_id": "string (references control-to-evidence matrix)",
  "timestamp": "ISO 8601 UTC",
  "source": "CI run URL | experiment report | benchmark output",
  "procedure": "link to test procedure",
  "result": "PASS | FAIL | WARNING",
  "metrics": { "key": "value" },
  "hash": "sha3-256 hex digest of the evidence payload",
  "signature": "HMAC-SHA256 of hash using certification signing key",
  "signed_by": "certification-engineer@cobalto",
  "chain_of_custody": [
    { "actor": "system", "action": "generated", "timestamp": "ISO 8601" },
    { "actor": "evidence-custodian", "action": "verified", "timestamp": "ISO 8601" }
  ]
}
```

### Certification Report

```json
{
  "report_id": "CER-YYYY-MM-DD-NNN",
  "version": "string",
  "domain": "string",
  "certification_level": "L1 | L2 | L3 | L4",
  "valid_from": "ISO 8601",
  "valid_until": "ISO 8601 (or 'event-driven')",
  "controls_certified": [
    {
      "control_id": "string",
      "status": "CERTIFIED | NOT_CERTIFIED | EXCEPTION",
      "evidence_artifact_id": "uuid-v4",
      "last_validated": "ISO 8601"
    }
  ],
  "exceptions": [
    {
      "control_id": "string",
      "rationale": "string",
      "approved_by": "certification-authority@cobalto"
    }
  ],
  "summary": {
    "total_controls": "int",
    "certified": "int",
    "not_certified": "int",
    "exceptions": "int",
    "coverage_pct": "float"
  }
}
```

### Chaos Experiment Report

```yaml
experiment:
  id: "CHAOS-YYYY-MM-DD-NNN"
  name: "string"
  hypothesis: "string"
  domain: "string"
  blast_radius: "pod | service | namespace | cluster"
  duration: "duration"
execution:
  start_time: "ISO 8601"
  end_time: "ISO 8601"
  target: "resource identifier"
  method: "pod-kill | network-chaos | stress-chaos | http-chaos"
  parameters: { key: value }
results:
  steady_state_before: { metrics }
  steady_state_during: { metrics }
  steady_state_after: { metrics }
  hypothesis_supported: true | false
  observations: "string"
  regressions: ["metric differences"]
rollback:
  method: "string"
  duration: "duration"
  verified: true | false
```

## CI Integration Points

| Pipeline Job | Cert Domain | Tool | Frequency |
|-------------|-------------|------|-----------|
| `unit-tests` | All | pytest | Every commit |
| `integration-tests` | Pipeline integrity | pytest | Every commit |
| `injection-fuzzing` | Security posture | pytest + prompt guard | Every commit |
| `e2e-tests` | Resilience | pytest + httpx | Label `e2e` |
| `performance-benchmark` | Performance | k6 | Label `perf`, push to main |
| `k8s-hardening` | Technology | kubectl + OPA | Every commit |
| Chaos day (scheduled) | Resilience + All | LitmusChaos + k6 | Weekly (Friday) |

## Storage & Retention

| Artifact Type | Store | Retention | Immutability |
|---------------|-------|-----------|-------------|
| Evidence artifacts | S3 (immutable bucket) | 10 years | S3 Object Lock (COMPLIANCE mode) |
| Chaos experiment reports | S3 + GitHub Actions artifacts | 3 years | SHA-256 manifest |
| Certification reports | `/certification/reports/` in repo | Permanent | Git commit history |
| Baseline benchmarks | `tests/benchmark/baselines/` in repo | Permanent | Git commit history |
| CI logs | GitHub Actions | 90 days | GitHub retention policy |
