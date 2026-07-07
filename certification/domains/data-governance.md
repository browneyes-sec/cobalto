# Data Governance Certification

> **Domain:** Encryption, key management, PII masking, data retention, data lifecycle  
> **Control Owner:** Infrastructure Owner  
> **Steady State:** 100% of data encrypted at rest and in transit, keys rotated within TTL, PII masked before logging, retention policies enforced

## Certification Scope

Certifies that the platform's data governance controls function correctly across the entire data lifecycle — from ingestion through processing, storage, archival, and deletion.

| Data Lifecycle Stage | Component | Governance Control |
|---------------------|-----------|-------------------|
| Collection | Wazuh → ES | TLS 1.3 transit encryption |
| Ingestion | POST /agent/analyze | PII masking before audit logging |
| Processing | LangGraph agent | No persistent local storage, in-memory only |
| Enrichment | OpenCTI / external APIs | API keys sourced from Vault, never logged |
| Storage | PostgreSQL, Elasticsearch, Qdrant, S3 | AES-256 at rest, KMS key rotation |
| Archival | S3-IA / S3-Glacier | Lifecycle policies, encryption at rest |
| Deletion | CronJob + lifecycle rules | Retention policy enforcement, deletion verification |
| Backup | S3 backup + snapshot | Encrypted snapshots, cross-region replication |

## Steady State Definition

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Encryption at rest coverage | 100% of data stores (ES, PG, Qdrant, S3) | Config audit |
| Encryption in transit coverage | 100% of service-to-service connections (TLS 1.3) | mTLS policy verification |
| PII masking completeness | 100% of PII fields masked in audit logs | Log inspection test |
| Key rotation compliance | 100% of keys rotated within TTL | Vault audit log review |
| Retention policy enforcement | 0% retention violations (data deleted before TTL) | S3 lifecycle policy audit |
| Data deletion verification | 100% of deletion operations logged and verified | Deletion log audit |

## Controls Under Certification

| Control ID | Control | Evidence | Test Procedure |
|-----------|---------|----------|---------------|
| DG-01 | TLS 1.3 for all service-to-service traffic | Istio mTLS configuration, Vault PKI certs | `compliance-evidence-test.sh` |
| DG-02 | AES-256 encryption at rest (all data stores) | KMS key policies, encryption configs | Config audit |
| DG-03 | Vault PKI with 24-hour certificate TTL | Vault PKI mount config, cert chain validation | `compliance-evidence-test.sh` |
| DG-04 | Vault dynamic secrets (database, API keys) | Dynamic DB engine config, rotation logs | Vault audit log |
| DG-05 | PII masking in audit logs | Log samples verified for PII redaction | Log inspection |
| DG-06 | Data retention policies enforced | S3 lifecycle rules, ES ILM policy | Policy audit |
| DG-07 | Data deletion verification | Deletion job logs, S3 object removal confirmation | `compliance-evidence-test.sh` |
| DG-08 | Backup encryption + integrity | Backup encryption config, restore test logs | DR test |
| DG-09 | Immutable audit log storage | ES WORM policy, S3 Object Lock config | Config audit |

## Controlled Data Classification

| Classification | Examples | Encryption | Retention | Masking |
|---------------|----------|------------|-----------|---------|
| **Critical** | Vault secrets, JWT signing keys, TLS private keys | AES-256 + HSM | 7 years | Never logged |
| **High** | Alert payloads with PII, incident case data | AES-256 | 10 years | PII masked in logs |
| **Medium** | Anonymized alerts, threat intel, MITRE mappings | AES-256 | 1–7 years | No PII present |
| **Low** | Metrics, health status, deployment config | N/A | 90 days | N/A |

## Chaos Experiments

| Experiment | Hypothesis | Blast Radius |
|-----------|-----------|-------------|
| [Secret rotation](../../chaos/experiments/secret-rotation.md) | Vault PKI cert rotation during load: no service disruption | Namespace |
| Key material corruption | KMS key disabled: read operations fail gracefully, writes queued | Service |
| Retention boundary | Data past retention date: deletion cronjob removes exactly at TTL | Storage |

## Test Coverage Requirements

- **Encryption verification:** Every data store configuration auditable for encryption settings
- **PII masking:** Regex-based audit log inspection for unmasked PII patterns
- **Retention enforcement:** CronJob execution history shows 100% on-time deletion
- **Key rotation:** Vault audit logs showing key rotation within every TTL window
- **Backup integrity:** Restore verification performed quarterly

## Certification Procedure

```bash
# 1. Audit encryption configuration
python3 certification/evidence/generate-package.py --domain data-governance --check encryption

# 2. Verify PII masking
python3 certification/evidence/generate-package.py --domain data-governance --check pii-masking

# 3. Validate retention policies
python3 certification/evidence/generate-package.py --domain data-governance --check retention

# 4. Verify key rotation
vault read -field=expiration pki/cert/$(vault list pki/certs | head -1)
vault read transit/keys/cobalto

# 5. Generate evidence package
python3 certification/evidence/generate-package.py --domain data-governance
```

## Current Status

| Control | L1 (CI Gate) | L2 (Validation) | L3 (Evidence) | L4 (Audit) |
|---------|:-------------:|:----------------:|:--------------:|:-----------:|
| DG-01 | ✅ mTLS config | ✅ Istio docs | ⏳ Template ready | ⏳ Planned |
| DG-02 | ✅ KMS config | ✅ Config docs | ⏳ Template ready | ⏳ Planned |
| DG-03 | ✅ Vault PKI setup | ✅ ADR-007 | ⏳ Template ready | ⏳ Planned |
| DG-04 | ✅ Vault dynamic DB | ⏳ Manual | ⏳ Pending | ⏳ Planned |
| DG-05 | ✅ Audit logger | ✅ Tested | ⏳ Template ready | ⏳ Planned |
| DG-06 | ✅ Retention docs | ⏳ Manual | ⏳ Template ready | ⏳ Planned |
| DG-07 | ⏳ Not implemented | ⏳ Pending | ⏳ Pending | ⏳ Planned |
| DG-08 | ✅ S3 encryption | ✅ Config docs | ⏳ Template ready | ⏳ Planned |
| DG-09 | ⏳ WORM policy pending | ⏳ Pending | ⏳ Pending | ⏳ Planned |
