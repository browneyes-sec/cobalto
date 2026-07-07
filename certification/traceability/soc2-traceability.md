# SOC 2 Type II Traceability Matrix

> Maps SOC 2 Trust Service Criteria to cobalto controls and evidence artifacts.  
> Covers all five Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, Privacy.

## TSC: Security (CC6.x–CC7.x)

| Criteria | Description | Cobalto Control | Control ID | Evidence Artifact |
|----------|-------------|----------------|-----------|------------------|
| **CC6.1** | Logical and physical access controls | Console JWT auth, API key HMAC auth, Vault secrets | SP-01, SP-03 | Auth logs (`evidence/soc2/auth-logs-*.json`) |
| **CC6.1** | Authentication and authorization | bcrypt passwords, token rotation, RBAC | SP-04, SP-05 | Access control matrix (`evidence/soc2/access-control.json`) |
| **CC6.1** | Restricting access to system components | K8s NetworkPolicy, mTLS, Vault policies | SP-12, DG-01 | Network isolation evidence (`evidence/soc2/network-policies.json`) |
| **CC6.2** | System operations and change management | CI pipeline, IaC (Kustomize), GitHub Actions | CM-05 | Deployment logs (`evidence/soc2/deployment-log.json`) |
| **CC6.2** | Configuration management | Version-controlled manifests, drift detection | CM-05 | Config diff reports (`evidence/soc2/config-diffs.json`) |
| **CC6.3** | Confidentiality protection | Data classification, encryption at rest/transit | DG-02, DG-05 | Data classification (`evidence/soc2/data-classification.json`) |
| **CC6.4** | System availability | PDBs, probes, resource limits, HPA | RS-01–RS-04 | Uptime metrics (`evidence/soc2/uptime-metrics.json`) |
| **CC6.5** | Access provisioning and deprovisioning | User management via Vault + console-auth | SP-03 | User lifecycle logs (`evidence/soc2/user-lifecycle.json`) |
| **CC7.1** | Threat detection | LangGraph agent pipeline, Wazuh SIEM alerts | CM-01 | Alert volume reports (`evidence/soc2/alert-volume.json`) |
| **CC7.1** | Monitoring and detection | Continuous monitoring, audit trail | CM-08, SP-07 | Audit log integrity (`evidence/soc2/audit-integrity.json`) |
| **CC7.2** | Incident response | Automated containment, escalation workflows | CM-07 | Incident timelines (`evidence/soc2/incident-timeline.json`) |
| **CC7.2** | Incident analysis | Threat intel enrichment, MITRE ATT&CK mapping | CM-03 | Incident analysis (`evidence/soc2/incident-analysis.json`) |
| **CC7.3** | Incident remediation | Response actions, n8n playbooks, TheHive cases | CM-07 | Response action logs (`evidence/soc2/response-actions.json`) |
| **CC7.4** | Incident communication | Escalation notifications, client reporting | CM-02 | Escalation logs (`evidence/soc2/escalations.json`) |

## TSC: Availability (CC6.4, CC8.1)

| Criteria | Description | Cobalto Control | Control ID | Evidence Artifact |
|----------|-------------|----------------|-----------|------------------|
| **A1.1** | System availability objectives | SLA definition, uptime monitoring | — | SLA document (`evidence/soc2/sla-definition.json`) |
| **A1.2** | Processing availability | PDBs, replication, auto-scaling | RS-01, RS-04 | Availability metrics (`evidence/soc2/availability.json`) |
| **A1.3** | Backup and recovery | S3 backup, snapshot, DR procedures | DG-08 | Backup verification (`evidence/soc2/backup-verification.json`) |
| **CC8.1** | Change management | CI/CD pipeline, testing gates, approval flows | CM-05 | Change records (`evidence/soc2/change-records.json`) |
| **CC8.1** | Emergency changes | Break-glass procedures, emergency access logs | — | Emergency change log (`evidence/soc2/emergency-changes.json`) |

## TSC: Processing Integrity (CC6.2, CC8.1)

| Criteria | Description | Cobalto Control | Control ID | Evidence Artifact |
|----------|-------------|----------------|-----------|------------------|
| **PI1.1** | Processing completeness | Pipeline integrity, alert dedup, HMAC receipts | PI-01–PI-08 | Pipeline integrity evidence (`evidence/soc2/pipeline-integrity.json`) |
| **PI1.2** | Processing accuracy | Input validation, schema lock, Pydantic models | PI-01, PI-02 | Validation logs (`evidence/soc2/validation-logs.json`) |
| **PI1.3** | Processing timeliness | SLA monitoring, benchmark baselines | PF-01–PF-05 | Performance metrics (`evidence/soc2/performance-metrics.json`) |
| **PI1.4** | Error handling | Graceful degradation, audit logging | PI-07 | Error logs (`evidence/soc2/error-logs.json`) |

## TSC: Confidentiality (CC6.3, CC6.5)

| Criteria | Description | Cobalto Control | Control ID | Evidence Artifact |
|----------|-------------|----------------|-----------|------------------|
| **C1.1** | Confidential information identification | Data classification framework | DG-05 | Classification policy (`evidence/soc2/data-classification.json`) |
| **C1.2** | Confidential information protection | Encryption at rest/transit, access controls | DG-01, DG-02 | Encryption status (`evidence/soc2/encryption-status.json`) |
| **C1.3** | Confidential information retention | Retention policies, automated deletion | DG-06 | Retention enforcement (`evidence/soc2/retention-enforcement.json`) |
| **C1.4** | Confidential information disposal | Secure deletion, data lifecycle cronjobs | DG-07 | Deletion verification (`evidence/soc2/deletion-log.json`) |

## TSC: Privacy (CC6.3, CC6.5)

| Criteria | Description | Cobalto Control | Control ID | Evidence Artifact |
|----------|-------------|----------------|-----------|------------------|
| **P1.1** | Personal information collection | Data inventory, purpose limitation | — | Data inventory (`evidence/soc2/data-inventory.json`) |
| **P1.2** | Personal information use | Data processing documentation | — | Processing records (`evidence/soc2/processing-records.json`) |
| **P4.1** | Access to personal information | PII masking in logs, access controls | DG-05 | Access logs with PII audit (`evidence/soc2/pii-access.json`) |
| **P5.1** | Personal information accuracy | Data validation, dedup mechanisms | PI-01 | Data quality reports (`evidence/soc2/data-quality.json`) |
| **P6.1** | Personal information disposal | Retention TTL, automated purge | DG-06, DG-07 | Purge verification logs (`evidence/soc2/purge-log.json`) |
| **P6.2** | Breach notification | Incident response, automated alerting | CM-07 | Breach notification logs (`evidence/soc2/breach-notifications.json`) |

## Evidence Collection Schedule

| Activity | Frequency | Responsible |
|----------|-----------|-------------|
| Auth log export | Continuous | Evidence Custodian |
| Deployment log export | Per deployment | CI Pipeline |
| Incident report generation | Per incident | Documentation Agent |
| Performance benchmark | Weekly (main push) | CI Pipeline |
| Backup verification | Weekly | Evidence Custodian |
| Access control review | Monthly | Control Owner |
| Vulnerability scan review | Weekly | Control Owner |
| SOC 2 evidence package assembly | Quarterly | Certification Engineer |
