# Compliance Domain — Controls CM-01 through CM-10

**Steady-State Hypothesis**: The platform maintains evidence artifacts that satisfy NIST CSF 2.0, SOC 2, ISO 27001, PCI DSS 4.0, and GDPR audit requirements.

## Controls

| ID | Control | Verification | Procedure |
|----|---------|-------------|-----------|
| CM-01 | NIST CSF DE.AE — Anomaly detection evidence | Alert events logged with source IP, severity, rule ID | compliance-evidence-test.sh |
| CM-02 | NIST CSF RS.CO — Communication evidence | Incident report contains escalation path | compliance-evidence-test.sh |
| CM-03 | NIST CSF RC.RP — Recovery planning evidence | Service recovers within SLO after restart | compliance-evidence-test.sh |
| CM-04 | SOC 2 A1.1 — Availability monitoring evidence | Uptime records exist in metrics | compliance-evidence-test.sh |
| CM-05 | SOC 2 CC6.1 — Logical access controls evidence | Auth middleware enforces API key validation | compliance-evidence-test.sh |
| CM-06 | ISO 27001 A.12.4 — Logging and monitoring evidence | Audit log entries are HMAC-signed and tamper-evident | compliance-evidence-test.sh |
| CM-07 | ISO 27001 A.16.1 — Incident management evidence | Incident reports contain full chain of custody | compliance-evidence-test.sh |
| CM-08 | PCI DSS 10.2 — Audit trail evidence | All access events logged with user, timestamp, and action | compliance-evidence-test.sh |
| CM-09 | PCI DSS 10.6 — Log review evidence | Audit entries are reviewable in structured format | compliance-evidence-test.sh |
| CM-10 | GDPR Art. 33 — Breach notification evidence | Alert pipeline timestamps support breach notification SLAs | compliance-evidence-test.sh |

## Steady-State Verification
- All required evidence directories exist
- Evidence schema is validated
- Chain-of-custody signatures are verifiable
