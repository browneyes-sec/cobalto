# MDR Operations Service

## SLA Tracking

The MDR Operations Service tracks and enforces Service Level Agreements for all monitored customers. SLA metrics are calculated from alert creation to resolution, with automatic escalation on breach.

### Priority Definitions

| Priority | Description | Response Time | Containment Time | Resolution Time | Breach Threshold |
|----------|-------------|---------------|-------------------|-----------------|------------------|
| P1 | Critical — Active breach, data exfiltration, ransomware | ≤ 15 min | ≤ 30 min | ≤ 4 hours | Immediate escalation to MDR Lead |
| P2 | High — Confirmed malicious activity, lateral movement | ≤ 30 min | ≤ 1 hour | ≤ 8 hours | Auto-escalate after 2× SLA |
| P3 | Medium — Suspicious activity, policy violation | ≤ 2 hours | ≤ 4 hours | ≤ 24 hours | Alert at 80% SLA consumed |
| P4 | Low — Informational, vulnerability scan findings | ≤ 8 hours | ≤ 24 hours | ≤ 72 hours | Alert at 90% SLA consumed |

### SLA Breach Detection

SLA tracking operates on a polling loop that checks every alert's timestamps against the defined thresholds:

1. **Response SLA:** Measured from `alert.created_at` to `first_agent_action.timestamp`.
2. **Containment SLA:** Measured from `alert.created_at` to `first_containment_action.timestamp`.
3. **Resolution SLA:** Measured from `alert.created_at` to `incident.resolved_at`.

On breach:
- Incident is flagged with `sla_breach: true`
- Notification sent to assigned analyst and shift lead
- For P1/P2: PagerDuty incident created automatically
- Breach metrics recorded for customer reporting

### Escalation Rules

| Condition | Action | Target |
|-----------|--------|--------|
| P1 not responded in 15 min | Auto-escalate | MDR Lead + Customer CISO |
| P2 not responded in 30 min | Auto-escalate | Shift Lead |
| P2 not contained in 1 hour | Auto-escalate | MDR Lead |
| P3 not responded in 2 hours | Notification | Assigned Analyst |
| P3 not contained in 4 hours | Auto-escalate | Shift Lead |
| P4 not responded in 8 hours | Notification | Assigned Analyst |
| Any priority SLA at 80% consumed | Warning | Assigned Analyst |
| Any priority SLA at 100% consumed | Breach | Shift Lead + Dashboard Alert |

## Reporting

### WeeklySummary

Generated every Monday at 08:00 UTC via K8s CronJob. Aggregated across all customers.

**Metrics included:**

| Metric | Description | Source |
|--------|-------------|--------|
| Total alerts ingested | Count of all received alerts | Elasticsearch |
| True positive rate | % of alerts confirmed as real threats | Agent state `false_positive_probability` |
| False positive rate | % of alerts dismissed as false | Agent state `false_positive_probability` |
| Mean Time to Respond (MTTR) | Average from alert creation to first action | Timestamps in agent state |
| Mean Time to Contain (MTTC) | Average from alert creation to containment | Timestamps in agent state |
| Mean Time to Resolve (MTTR₂) | Average from alert creation to resolution | Incident lifecycle timestamps |
| Incidents created | Total incidents generated | TheHive case count |
| Escalations | Incidents escalated beyond normal flow | Escalation agent logs |
| SLA breaches | Number of SLA breaches by priority | SLA tracking system |
| Agent accuracy | % of correct triage decisions | Historical comparison |

### CustomerReport

Per-customer report generated on demand or weekly.

**Additional per-customer metrics:**

| Metric | Description |
|--------|-------------|
| Customer name | Organization identifier |
| Assets monitored | Number of hosts/endpoints under monitoring |
| Alert volume trend | Week-over-week alert count change |
| Top MITRE techniques | Most frequently observed techniques |
| Threat actor activity | Known threat actors targeting this customer |
| Recommended actions | Proactive security recommendations |

### Report Delivery

- **WeeklySummary:** Emailed to MDR team distribution list, uploaded to S3
- **CustomerReport:** Emailed to customer security contact, uploaded to S3, available in Cobalt Console
- **Format:** HTML email body + PDF attachment (generated via WeasyPrint)

## Scheduling

### Shift Schedule

The MDR team operates on a 3-shift model covering 24/7/365.

| Shift | Hours (UTC) | Hours (EST) | Staffing |
|-------|-------------|-------------|----------|
| DAY | 06:00–14:00 | 01:00–09:00 | 2 Senior Analysts, 1 Junior Analyst |
| EVENING | 14:00–22:00 | 09:00–17:00 | 2 Senior Analysts, 1 Junior Analyst |
| NIGHT | 22:00–06:00 | 17:00–01:00 | 1 Senior Analyst, 1 Junior Analyst |

**Shift overlap:** 15 minutes between shifts for handoff briefing.

**On-call rotation:** One senior analyst is on-call outside shift hours for P1 escalations. PagerDuty manages the rotation.

### Shift Handoff Protocol

1. Outgoing shift lead compiles a handoff brief listing:
   - Active incidents and their current state
   - Pending approvals
   - Notable trends observed during shift
   - SLA risks (alerts approaching breach)
2. Incoming shift lead reviews the brief and acknowledges in Slack.
3. Handoff brief is persisted to the audit log.

### Alert Assignment

Alerts are assigned to analysts based on severity and expertise:

| Rule | Condition | Assignment |
|------|-----------|------------|
| Severity routing | `severity == "P1"` | Senior analyst with lowest active load |
| Severity routing | `severity == "P2"` | Senior analyst with domain expertise |
| Severity routing | `severity == "P3"` | Any available analyst (round-robin) |
| Severity routing | `severity == "P4"` | Junior analyst (training opportunity) |
| Domain matching | MITRE technique involves cloud | Cloud-specialized analyst |
| Domain matching | MITRE technique involves network | Network-specialized analyst |
| Domain matching | MITRE technique involves endpoint | Endpoint-specialized analyst |
| Load balancing | Active incident count > 5 | Overflow to next available analyst |
| Escalation | Analyst offline > 15 min | Reassign to shift lead |

### Analyst Profile

```python
class Analyst:
    id: str                        # Unique analyst identifier
    name: str                      # Full name
    role: Literal["junior", "senior", "lead"]
    shift: Literal["DAY", "EVENING", "NIGHT"]
    expertise: list[str]           # MITRE tactics of specialization
    max_concurrent_incidents: int  # 3 junior, 5 senior, 8 lead
    is_on_call: bool               # Currently on-call for escalations
    pagerduty_id: str              # PagerDuty user ID
```

## Deployment

### K8s CronJob for Daily Report Generation

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: mdr-weekly-report
  namespace: cobalt
spec:
  schedule: "0 8 * * 1"  # Every Monday at 08:00 UTC
  successfulJobsHistoryLimit: 5
  failedJobsHistoryLimit: 3
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: mdr-ops
          containers:
            - name: report-generator
              image: ghcr.io/cobalto/mdr-ops:latest
              command:
                - python
                - -m
                - mdr_ops.reports.generate_weekly
              env:
                - name: DATABASE_URL
                  valueFrom:
                    secretKeyRef:
                      name: mdr-secrets
                      key: database-url
                - name: ELASTICSEARCH_URL
                  value: "http://elasticsearch:9200"
                - name: S3_BUCKET
                  value: "cobalto-reports"
                - name: SMTP_HOST
                  value: "smtp.cobalto.internal"
                - name: REPORT_RECIPIENTS
                  valueFrom:
                    configMapKeyRef:
                      name: mdr-config
                      key: report-recipients
              resources:
                requests:
                  memory: "512Mi"
                  cpu: "250m"
                limits:
                  memory: "1Gi"
                  cpu: "1000m"
          restartPolicy: OnFailure
          backoffLimit: 3
```

### K8s CronJob for SLA Monitoring

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: sla-monitor
  namespace: cobalt
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: mdr-ops
          containers:
            - name: sla-checker
              image: ghcr.io/cobalto/mdr-ops:latest
              command:
                - python
                - -m
                - mdr_ops.sla.check_breaches
              env:
                - name: DATABASE_URL
                  valueFrom:
                    secretKeyRef:
                      name: mdr-secrets
                      key: database-url
                - name: PAGERDUTY_TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: mdr-secrets
                      key: pagerduty-token
              resources:
                requests:
                  memory: "256Mi"
                  cpu: "100m"
                limits:
                  memory: "512Mi"
                  cpu: "500m"
          restartPolicy: OnFailure
```
