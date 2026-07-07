# Compliance Certification

> **Domain:** Regulatory framework alignment — SOC 2, NIST CSF 2.0, PCI DSS 4.0, HIPAA, GDPR  
> **Control Owner:** Compliance Lead / Security Engineer  
> **Steady State:** Evidence artifacts auto-generated for all certified controls, traceability matrix 100% mapped

## Certification Scope

Certifies that the platform generates sufficient evidence for SOC 2 Type II, NIST CSF 2.0 Tier 4, PCI DSS 4.0 (relevant requirements), and HIPAA Security Rule alignment.

| Framework | Coverage Level | Target |
|-----------|---------------|--------|
| NIST CSF 2.0 | Full — all 6 functions | Tier 4 (Adaptive) |
| SOC 2 Type II | All 5 Trust Service Criteria | Auditor-ready evidence package |
| PCI DSS 4.0 | Requirements 10, 11, 12 | Evidence generation automated |
| HIPAA Security Rule | Administrative + Technical safeguards | Control mapping complete |
| ISO 27001:2022 | Relevant Annex A controls | Partial alignment |
| GDPR | Data processing principles | Data governance controls |

## Steady State Definition

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Control-to-evidence mapping coverage | 100% of mandatory controls mapped | Traceability matrix audit |
| Evidence artifact generation | 100% automated (no manual collection) | CI pipeline verification |
| Evidence retention compliance | All artifacts stored with correct TTL | S3 lifecycle policy review |
| Audit trail completeness | Every request logged with HMAC | Log count vs. request count |
| Evidence signature validity | 100% of artifacts HMAC-signed | Signature verification script |

## Controls Under Certification

| Control ID | Framework | Control | Evidence Type |
|-----------|-----------|---------|--------------|
| CM-01 | NIST CSF DE.CM | Continuous monitoring of security events | Agent audit logs |
| CM-02 | NIST CSF RS.RP | Documented response procedures | Incident reports |
| CM-03 | NIST CSF ID.RA | Risk assessment on alerts | Alert classification reports |
| CM-04 | SOC 2 CC6.1 | Logical access controls | Auth logs, key rotation reports |
| CM-05 | SOC 2 CC6.2 | System operations + change management | CI pipeline logs, deployment records |
| CM-06 | SOC 2 CC7.1 | Threat detection | Alert volume reports |
| CM-07 | SOC 2 CC7.2 | Incident response | Incident timelines, SLA reports |
| CM-08 | PCI 10.2 | Automated audit trails | Immutable audit index |
| CM-09 | PCI 10.5 | Audit trail retention | S3 lifecycle policy |
| CM-10 | PCI 11.1 | Security testing | Vulnerability scan results |
| CM-11 | HIPAA §164.308(a)(1) | Security management process | Risk assessment reports |
| CM-12 | HIPAA §164.312(a) | Access control | Auth logs, RBAC config |
| CM-13 | HIPAA §164.312(b) | Audit controls | Audit trail generation |
| CM-14 | HIPAA §164.312(c) | Integrity controls | HMAC receipt verification |
| CM-15 | HIPAA §164.312(e) | Transmission security | TLS/mTLS configuration |
| CM-16 | GDPR Art. 5(1)(e) | Storage limitation | Retention policy config |
| CM-17 | GDPR Art. 5(1)(f) | Integrity + confidentiality | Encryption + access logs |

## Evidence Generation

Evidence artifacts must be generated programmatically and follow the schema defined in `governance/tools-and-artifacts.md`.

### Evidence Pipeline

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  CI Pipeline  │───▶│  Evidence     │───▶│  Signature    │───▶│  Evidence     │
│  (trigger)    │    │  Generator    │    │  (HMAC-SHA3)  │    │  Bucket (S3)  │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                           │                                        │
                           ▼                                        ▼
                    ┌──────────────┐                        ┌──────────────┐
                    │  Control-to- │                        │  Chain of     │
                    │  Evidence    │                        │  Custody Log  │
                    │  Matrix      │                        │               │
                    └──────────────┘                        └──────────────┘
```

### Evidence Artifacts Per Framework

| Framework | Key Evidence Artifacts | Automation Level |
|-----------|----------------------|-----------------|
| NIST CSF | Agent audit logs, incident reports, alert classification, SLA dashboards | Automated |
| SOC 2 | Access logs, change management records, incident timelines, uptime reports | Automated |
| PCI DSS | Audit trail logs, vulnerability scans, retention configs | Automated |
| HIPAA | Risk assessments, access logs, integrity verifications, encryption configs | Automated |
| GDPR | Data inventory, retention policies, deletion logs | Partially automated |

## Test Coverage Requirements

- **Traceability verification:** Script checks every mapped control has a corresponding evidence template
- **Evidence generation:** Each evidence template produces valid output (valid JSON schema, valid HMAC signature)
- **Retention verification:** S3 lifecycle policy matches documented retention periods
- **Access control verification:** Every service account has documented RBAC

## Certification Procedure

```bash
# 1. Validate traceability matrix completeness
python3 certification/traceability/validate-matrix.py

# 2. Generate all evidence artifacts
python3 certification/evidence/generate-package.py --domain compliance --framework all

# 3. Verify evidence signatures
python3 certification/evidence/verify-signatures.py

# 4. Export compliance dashboard
python3 certification/reports/generate-report.py --framework nist-csf --output compliance-report.pdf

# 5. Publish evidence package
aws s3 sync certification/evidence/ s3://cobalto-compliance-evidence/ \
  --sse-kms-key-id alias/compliance-evidence-key
```

## Current Status

| Control | L1 (CI Gate) | L2 (Validation) | L3 (Evidence) | L4 (Audit) |
|---------|:-------------:|:----------------:|:--------------:|:-----------:|
| CM-01 | ✅ Audit logs | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-02 | ✅ Incident reports | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-03 | ✅ Alert classification | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-04 | ✅ Auth logs | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-05 | ✅ CI pipeline logs | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-06 | ✅ Alert volume metrics | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-07 | ✅ Incident timelines | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-08 | ✅ Audit trail | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-09 | ✅ Retention config | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-10 | ✅ Trivy scanning | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-11 | ⏳ Template ready | ⏳ Automated | ⏳ Pending | ⏳ Planned |
| CM-12 | ✅ Auth logs | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-13 | ✅ Audit trail | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-14 | ✅ HMAC receipts | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-15 | ✅ mTLS config | ✅ Validated | ⏳ Template ready | ⏳ Planned |
| CM-16 | ✅ Retention policies | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| CM-17 | ✅ Encryption + logs | ✅ Automated | ⏳ Template ready | ⏳ Planned |
