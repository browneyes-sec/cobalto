# Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for responding to security incidents detected by the Cobalto platform.

## Severity Levels

| Level | Description | Response Time | Escalation |
|-------|-------------|---------------|------------|
| **Critical** | Active compromise, data breach, ransomware | Immediate | CISO, Legal |
| **High** | Confirmed malicious activity | 15 minutes | SOC Lead |
| **Medium** | Suspicious activity requiring investigation | 1 hour | SOC Analyst |
| **Low** | Policy violation, informational | 4 hours | Standard |

## Response Procedures

### 1. Initial Triage (Automated)

The Triage Agent automatically:
- Parses alert payload
- Extracts IOCs (IPs, domains, hashes, users)
- Classifies alert type
- Assigns severity score
- Generates investigation steps

**Manual Override:**
```bash
# Trigger manual triage
curl -X POST http://localhost:8001/agent/triage \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "manual-001", "alert": {...}}'
```

### 2. Deep Analysis (Automated)

The Analysis Agent:
- Maps to MITRE ATT&CK techniques
- Correlates with threat intelligence
- Builds attack narrative
- Assesses risk score
- Generates recommendations

**Manual Trigger:**
```bash
curl -X POST http://localhost:8001/agent/analyze-deep \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "alert-001", "alert": {...}}'
```

### 3. Threat Intelligence Correlation

The Threat Intel Agent:
- Queries OpenCTI for indicator matches
- Identifies potential threat actors
- Correlates with known campaigns
- Assesses threat level

**Manual Trigger:**
```bash
curl -X POST http://localhost:8001/agent/threat-intel \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "alert-001", "indicators": [...]}'
```

### 4. Response Action Generation

The Response Agent:
- Generates containment actions
- Creates remediation plan
- Determines approval requirements
- Builds rollback plan

**Manual Trigger:**
```bash
curl -X POST http://localhost:8001/agent/response \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "alert-001", "alert": {...}}'
```

### 5. Human Approval (Slack)

For high-risk actions, approval is required:
1. Alert posted to #soc-approvals
2. Analyst reviews action plan
3. Clicks Approve/Reject
4. Actions executed upon approval

### 6. Containment Execution

Automated containment actions:
- **Block IP**: Firewall API integration
- **Isolate Host**: Wazuh Active Response
- **Disable User**: Active Directory API

**Manual Execution:**
```bash
# Block IP via Wazuh
curl -X PUT https://wazuh:55000/active-response/agent-001 \
  -u wazuh:password \
  -d '{"command": "firewall-drop", "arguments": ["add", "203.0.113.45"]}'
```

### 7. Documentation & Case Update

The Documentation Agent:
- Generates incident report
- Updates TheHive case
- Creates timeline
- Documents evidence

## Common Scenarios

### Brute Force Attack

1. **Detection**: Wazuh rule 5712 triggers
2. **Triage**: Identifies source IP, target user
3. **Analysis**: Maps to T1110 (Brute Force)
4. **Response**: 
   - Block source IP
   - Reset affected passwords
   - Enable MFA
5. **Documentation**: Create case in TheHive

### Malware Detection

1. **Detection**: EDR/AV alert triggers
2. **Triage**: Identifies malware hash, affected host
3. **Analysis**: Maps to T1059 (Execution)
4. **Response**:
   - Isolate affected host
   - Quarantine malware
   - Full system scan
5. **Documentation**: Create forensic image

### Data Exfiltration

1. **Detection**: DLP alert or anomalous traffic
2. **Triage**: Identifies destination, data type
3. **Analysis**: Maps to T1041 (Exfiltration)
4. **Response**:
   - Block destination IP
   - Isolate source host
   - Review access logs
5. **Documentation**: Breach assessment

## Escalation Procedures

### Auto-Escalation Triggers

- Critical severity alerts
- Multiple related alerts within 1 hour
- Threat actor attribution
- Data breach indicators
- Ransomware behavior

### Escalation Contacts

| Role | Contact | Availability |
|------|---------|--------------|
| SOC Lead | soc-lead@cobalto.io | 24/7 |
| CISO | ciso@cobalto.io | Business hours |
| Legal | legal@cobalto.io | Business hours |
| PR | pr@cobalto.io | On-call |

## Post-Incident

1. **Review**: Conduct post-incident review
2. **Lessons**: Document lessons learned
3. **Improve**: Update detection rules
4. **Train**: Update training materials

## Appendix

### Useful Commands

```bash
# Check Wazuh agents
curl -u wazuh:password https://wazuh:55000/agents

# Query OpenCTI
curl -X POST http://opencti:4000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query": "{ indicators(first: 10) { edges { node { name } } } }"}'

# Check TheHive cases
curl -H "Authorization: Bearer $TOKEN" http://thehive:9000/api/v1/case

# View n8n executions
curl -u admin:password http://n8n:5678/api/v1/executions
```

### Log Locations

| Service | Log Location |
|---------|--------------|
| LangGraph API | stdout (Docker logs) |
| n8n | /home/node/.n8n/logs |
| Wazuh | /var/ossec/logs |
| OpenCTI | /var/log/opencti |
| TheHive | /var/log/thehive |