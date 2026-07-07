# NIST CSF 2.0 Traceability Matrix

> Maps NIST Cybersecurity Framework 2.0 functions to cobalto controls and evidence artifacts.  
> Target maturity: **Tier 4 (Adaptive)** for Detect and Respond functions.

## Function: Identify (ID)

| Category | Subcategory | Cobalto Control | Control ID | Evidence Artifact |
|----------|------------|----------------|-----------|------------------|
| ID.AM — Asset Management | ID.AM-1: Physical devices and systems | Wazuh agent telemetry, endpoint inventory | CM-01 | Asset inventory reports (`evidence/compliance/asset-inventory.json`) |
| ID.AM | ID.AM-2: Software platforms and applications | Wazuh vulnerability detection, software inventory | CM-10 | Vulnerability scan results (`evidence/compliance/vulnerability-scans.json`) |
| ID.AM | ID.AM-5: Resources (people, technology) | Stakeholder map, RACI matrix | — | `docs/context/stakeholder-map.md` |
| ID.RA — Risk Assessment | ID.RA-1: Vulnerability identification | Wazuh vulnerability assessment, Trivy scanning | CM-10 | CVE reports (`evidence/compliance/cve-reports.json`) |
| ID.RA | ID.RA-3: Threat identification | Threat Intel Agent, MITRE ATT&CK mapping | CM-01 | Threat landscape reports (`evidence/compliance/threat-landscape.json`) |
| ID.RA | ID.RA-6: Risk response | Automated risk scoring on alerts | CM-03 | Alert classification reports (`evidence/compliance/alert-classification.json`) |
| ID.IM — Improvement | ID.IM-1: Improvement from incident response | Post-incident review, agent performance metrics | CM-02 | Incident post-mortems (`evidence/compliance/post-mortems/`) |

## Function: Protect (PR)

| Category | Subcategory | Cobalto Control | Control ID | Evidence Artifact |
|----------|------------|----------------|-----------|------------------|
| PR.AC — Access Control | PR.AC-1: Identity management | Console JWT auth, API key auth | SP-01, SP-03 | Auth logs (`evidence/compliance/auth-logs.json`) |
| PR.AC | PR.AC-3: Remote access | mTLS for service-to-service, Vault PKI | DG-01, DG-03 | Certificate inventory (`evidence/compliance/certificates.json`) |
| PR.AC | PR.AC-4: Access permissions | RBAC, least-privilege K8s RBAC, NetworkPolicy | SP-12 | RBAC config (`evidence/compliance/rbac-config.json`) |
| PR.AC | PR.AC-6: Least privilege | Container securityContext, capability drop ALL | SP-11 | securityContext audit (`evidence/compliance/security-context.json`) |
| PR.DS — Data Security | PR.DS-1: Data at rest | AES-256 encryption (ES, PG, Qdrant, S3) | DG-02 | KMS key policies (`evidence/compliance/kms-config.json`) |
| PR.DS | PR.DS-2: Data in transit | TLS 1.3, Istio mTLS | DG-01 | TLS config audit (`evidence/compliance/tls-config.json`) |
| PR.DS | PR.DS-4: Data retention | Configurable TTL, automated archival/purge | DG-06 | Retention policies (`evidence/compliance/retention-policies.json`) |
| PR.PT — Platform Security | PR.PT-1: Audit/log records | HMAC-signed audit logging | SP-07 | Audit logs (`evidence/audit/`) |
| PR.PT | PR.PT-3: Configuration management | IaC (Kustomize + Kubernetes manifests), version control | CM-05 | Git commit history (`evidence/compliance/change-log.json`) |

## Function: Detect (DE)

| Category | Subcategory | Cobalto Control | Control ID | Evidence Artifact |
|----------|------------|----------------|-----------|------------------|
| DE.CM — Continuous Monitoring | DE.CM-1: Network monitoring | Wazuh network analysis, traffic anomaly detection | CM-01 | Network alerts (`evidence/compliance/network-alerts.json`) |
| DE.CM | DE.CM-3: Personnel activity | User access logs, audit trail | SP-03, SP-07 | User activity logs (`evidence/compliance/user-activity.json`) |
| DE.CM | DE.CM-4: Malicious code detection | Wazuh malware detection, behavioral analysis | CM-01 | Malware alerts (`evidence/compliance/malware-alerts.json`) |
| DE.CM | DE.CM-7: Monitoring for unauthorized personnel | Auth middleware, API key validation | SP-01 | Auth failures log (`evidence/compliance/auth-failures.json`) |
| DE.CM | DE.CM-8: Vulnerability scanning | Wazuh vulnerability assessment, Trivy | CM-10 | Scan reports (`evidence/compliance/scan-reports/`) |
| DE.AE — Adverse Event Analysis | DE.AE-1: Event aggregation | Wazuh event correlation, agent pipeline | PI-06 | Pipeline logs (`evidence/compliance/pipeline-logs.json`) |
| DE.AE | DE.AE-2: Event correlation analysis | LangGraph triage, analysis, threat intel agents | PI-06 | Alert enrichment logs (`evidence/compliance/enrichment-logs.json`) |
| DE.AE | DE.AE-3: Event categorization | Alert severity classification (LOW → CRITICAL) | CM-03 | Alert classification (`evidence/compliance/alert-classification.json`) |

## Function: Respond (RS)

| Category | Subcategory | Cobalto Control | Control ID | Evidence Artifact |
|----------|------------|----------------|-----------|------------------|
| RS.RP — Response Planning | RS.RP-1: Response plan | Documented playbooks, n8n workflows | CM-02 | Playbook library (`evidence/compliance/playbooks/`) |
| RS.CO — Communications | RS.CO-2: Stakeholder notification | Escalation workflows, Slack/PagerDuty integration | CM-02 | Escalation logs (`evidence/compliance/escalation-logs.json`) |
| RS.CO | RS.CO-3: Shared reporting | Executive dashboards, client reports | — | Reports (`certification/reports/`) |
| RS.AN — Analysis | RS.AN-1: Incident investigation | Agent analysis, TheHive case management | CM-07 | Incident reports (`evidence/compliance/incidents/`) |
| RS.AN | RS.AN-3: Forensic analysis | IOC enrichment, threat intel correlation | CM-01 | Forensic evidence (`evidence/compliance/forensic/`) |
| RS.MI — Mitigation | RS.MI-1: Containment | Automated response actions (Wazuh API) | CM-07 | Response logs (`evidence/compliance/response-actions.json`) |
| RS.MI | RS.MI-2: Eradication | Remediation workflows, n8n playbooks | CM-07 | Remediation logs (`evidence/compliance/remediation.json`) |
| RS.IM — Improvement | RS.IM-1: Lessons learned | Post-incident review process | CM-02 | Post-mortem reports (`evidence/compliance/post-mortems/`) |

## Function: Recover (RC)

| Category | Subcategory | Cobalto Control | Control ID | Evidence Artifact |
|----------|------------|----------------|-----------|------------------|
| RC.RP — Recovery Planning | RC.RP-1: Recovery plan | DR procedures, backup/restore workflows | RS-04 | DR plan (`evidence/compliance/dr-plan.json`) |
| RC.IM — Improvement | RC.IM-1: Recovery improvement | DR test results, improvement backlog | — | DR test reports (`evidence/compliance/dr-tests/`) |
| RC.CO — Communications | RC.CO-2: Stakeholder communication | Post-incident reporting to clients | — | Client reports (`certification/reports/client/`) |

## Maturity Assessment

| Function | Current Tier | Target Tier | Gap |
|----------|-------------|-------------|-----|
| Identify (ID) | Tier 3 (Repeatable) | Tier 4 (Adaptive) | Continuous asset discovery automation |
| Protect (PR) | Tier 3 (Repeatable) | Tier 4 (Adaptive) | Behavioral threat modeling |
| Detect (DE) | Tier 3 (Repeatable) | Tier 4 (Adaptive) | Autonomous detection tuning |
| Respond (RS) | Tier 3 (Repeatable) | Tier 4 (Adaptive) | Self-improving playbooks |
| Recover (RC) | Tier 2 (Risk Informed) | Tier 3 (Repeatable) | Automated recovery verification |
