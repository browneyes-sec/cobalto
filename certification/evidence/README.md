# Evidence Collection

> Auto-generated evidence artifacts for certification audits.  
> **Principle:** All evidence is generated programmatically — no manual collection.

## Directory Structure

```
evidence/
├── pipeline/          # Pipeline integrity evidence
│   ├── validation-logs.json
│   ├── schema-enforcement.json
│   ├── hmac-receipts.json
│   ├── state-integrity.json
│   ├── pipeline-completions.json
│   └── error-logs.json
├── security/          # Security posture evidence
│   ├── auth-middleware.json
│   ├── console-auth.json
│   ├── injection-guard.json
│   ├── rate-limiter.json
│   ├── audit-log.json
│   ├── network-policies.json
│   └── security-context.json
├── resilience/        # Resilience evidence
│   ├── pdb-config.json
│   ├── degradation-test.json
│   └── chaos-results/
│       ├── pod-failure-*.json
│       ├── network-partition-*.json
│       └── load-spike-*.json
├── performance/       # Performance evidence
│   ├── alert-ingestion.json
│   ├── agent-latency.json
│   ├── auth-latency.json
│   ├── health-latency.json
│   └── baseline-comparison.json
├── compliance/        # Compliance evidence
│   ├── monitoring-logs.json
│   ├── incident-reports/
│   ├── access-controls.json
│   ├── change-management.json
│   ├── audit-trail.json
│   └── retention-config.json
├── governance/        # Data governance evidence
│   ├── tls-config.json
│   ├── encryption-config.json
│   ├── vault-pki.json
│   ├── pii-masking.json
│   └── retention-policies.json
└── reports/           # Certification reports
    ├── weekly-*.md
    └── audit-packages/
```

## Evidence Lifecycle

```
1. GENERATE — Test procedure produces evidence artifact
2. SIGN    — HMAC-SHA256 signature applied
3. VERIFY  — Automated integrity check
4. STORE   — Immutable evidence bucket (S3 Object Lock)
5. ARCHIVE — After retention period (Glacier)
6. AUDIT   — Produced on demand for auditor
```

## Evidence Schema

Every evidence artifact follows this schema:

```json
{
  "artifact_id": "uuid-v4",
  "domain": "string",
  "control_id": "string",
  "timestamp": "ISO 8601 UTC",
  "source": "CI run URL | procedure name",
  "procedure": "certification/procedures/<name>.sh",
  "result": "PASS | FAIL | WARNING",
  "metrics": {},
  "hash": "sha3-256 hex digest",
  "signature": "HMAC-SHA256",
  "signed_by": "certification-engineer@cobalto",
  "chain_of_custody": [
    { "actor": "system", "action": "generated", "timestamp": "ISO 8601" },
    { "actor": "evidence-custodian", "action": "verified", "timestamp": "ISO 8601" }
  ]
}
```

## Evidence Generation

```bash
# Generate evidence for all domains
python3 certification/evidence/generate-package.py --domain all

# Generate evidence for specific domain
python3 certification/evidence/generate-package.py --domain pipeline-integrity

# Verify evidence signatures
python3 certification/evidence/verify-signatures.py

# Package for auditor
python3 certification/evidence/package-for-audit.py --framework soc2
```

## Storage

| Environment | Storage | Retention | Immutability |
|-------------|---------|-----------|-------------|
| Development | Local filesystem (git-ignored) | Until next run | None |
| CI | GitHub Actions artifacts | 90 days | None |
| Staging | S3 bucket (versioned) | 3 years | S3 Object Lock (GOVERNANCE) |
| Production | S3 bucket (immutable) | 10 years | S3 Object Lock (COMPLIANCE) |
| Audit | Encrypted USB / secure FTP | Per auditor request | Tamper-evident seals |

## Chain of Custody

Every evidence access is logged:

```json
{
  "artifact_id": "uuid-v4",
  "events": [
    {
      "timestamp": "2026-07-06T12:00:00Z",
      "actor": "certification-engineer@cobalto",
      "action": "generated",
      "source": "CI run #1234"
    },
    {
      "timestamp": "2026-07-06T12:05:00Z",
      "actor": "evidence-custodian@cobalto",
      "action": "verified",
      "hash_match": true,
      "signature_valid": true
    }
  ]
}
```
