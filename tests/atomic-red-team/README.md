# Atomic Red Team Test Plan — Cobalto SOC/MDR Validation

## Purpose

Validate detection coverage of the Cobalto SOC/MDR platform against known ATT&CK techniques using Atomic Red Team tests.

## ATT&CK Techniques

| ID | Technique | Platform | Test Script | Detection Source | Expected Alert |
|----|-----------|----------|-------------|------------------|----------------|
| T1110 | Brute Force | Windows, Linux | `T1110.001-Password Guessing` | Wazuh auth logs | SSH brute force rule 800100 |
| T1078 | Valid Accounts | Windows, Linux | `T1078.001-Default Accounts` | Wazuh FIM + auth | Anomalous login rule 800110 |
| T1059 | Command and Scripting Interpreter | Windows, Linux | `T1059.001-PowerShell` | Wazuh sysmon | Suspicious process rule 800200 |
| T1021 | Remote Services | Windows | `T1021.001-RDP` | Wazuh RDP logs | Lateral movement rule 800210 |
| T1566 | Phishing | Windows | `T1569.001-Spearphishing Link` | Email gateway + Wazuh | Phishing indicator rule 800300 |
| T1071 | Application Layer Protocol | Windows, Linux | `T1071.001-Web Protocols` | Wazuh web proxy | C2 communication rule 800400 |

## Execution Steps

1. Deploy Atomic Red Team test infrastructure in isolated test namespace
2. Run each atomic test with proper isolation controls
3. Verify Wazuh agent captures logs for each technique
4. Confirm LangGraph agent receives and processes alerts
5. Validate OpenCTI enrichment returns relevant threat intelligence
6. Verify Cortex analysis produces accurate IOC reports
7. Check that SOC alerts appear in Wazuh dashboard with correct severity
8. Confirm incident tickets are auto-created in TheHive

## Prerequisites

- Wazuh agents installed on test endpoints
- Atomic Red Team binaries available in test environment
- Network isolation to prevent test traffic from escaping
- Snapshot/restore capability for clean test state

## Notes

- Run tests during maintenance windows only
- Document any detection gaps for rule tuning
- Update this file as new ATT&CK techniques are added
