# Operational Principles

> How the Cobalto Agentic SOC/MDR platform operates in production.

---

## 1. SLA Philosophy

### Response Time SLAs

| Priority | Definition | Response Time | Resolution Target | Breach Action |
|---|---|---|---|---|
| P1 (CRITICAL) | Active breach, data exfiltration, ransomware | 15 minutes | 4 hours | Auto-escalate to CISO |
| P2 (HIGH) | Confirmed compromise, lateral movement | 1 hour | 8 hours | Auto-escalate to L3 |
| P3 (MEDIUM) | Suspicious activity, policy violation | 4 hours | 24 hours | Auto-escalate to L2 |
| P4 (LOW) | Informational, routine monitoring | 24 hours | 72 hours | Log for review |

### SLA Enforcement

```go
// pkg/sla/enforcer.go
type SLAEnforcer struct {
    breaches   prometheus.Counter
    escalation *EscalationManager
}

func (e *SLAEnforcer) Check(incident Incident) {
    elapsed := time.Since(incident.CreatedAt)
    slaLimit := e.getSLALimit(incident.Severity)

    if elapsed > slaLimit {
        e.breaches.WithLabelValues(incident.Severity).Inc()
        e.escalation.Escalate(incident, "SLA_BREACH")
    }
}

func (e *SLAEnforcer) getSLALimit(severity string) time.Duration {
    switch severity {
    case "CRITICAL": return 15 * time.Minute
    case "HIGH":     return 1 * time.Hour
    case "MEDIUM":   return 4 * time.Hour
    case "LOW":      return 24 * time.Hour
    default:         return 24 * time.Hour
    }
}
```

---

## 2. Escalation Model

### Tiered Response Chain

```
Initial Detection (AI Triage)
  ↓ (confidence < 0.7 or containment required)
L1 Analyst (Automated enrichment + recommendation)
  ↓ (no response in 15 min or P1/P2 incident)
L2 Analyst (Manual investigation + approval)
  ↓ (no response in 30 min or complex incident)
L3 Analyst (Senior investigator + forensic analysis)
  ↓ (no response in 1 hour or breach confirmed)
CISO (Executive decision + client notification)
```

### Escalation Rules

| Trigger | Escalation Target | Timeout |
|---|---|---|
| Agent confidence < 0.7 | L1 Analyst | Immediate |
| Containment action required | L2 Analyst | Immediate |
| P1 incident detected | L2 Analyst | Immediate |
| SLA breach (P1) | CISO | 15 min |
| SLA breach (P2) | L3 Analyst | 1 hour |
| 3+ false positives in 1 hour | L2 Analyst | Immediate |
| LLM unavailable | L1 Analyst (manual triage) | Immediate |
| Client explicitly requests | Custom escalation path | Immediate |

### Escalation Payload

```json
{
  "escalation_id": "esc-2024-01-15-001",
  "incident_id": "inc-2024-01-15-042",
  "severity": "CRITICAL",
  "reason": "SLA_BREACH",
  "elapsed": "16m30s",
  "reasoning_trace": { "... full trace ..." },
  "recommended_action": "Isolate host 192.168.1.50 immediately",
  "escalated_to": "ciso@company.com",
  "escalated_at": "2024-01-15T10:46:30Z"
}
```

---

## 3. Shift Pattern

### 24/7 Coverage Model

| Shift | Hours (Local) | Coverage | Focus |
|---|---|---|---|
| DAY | 06:00–14:00 | Full L1 + L2 | Active investigation, client comms |
| EVENING | 14:00–22:00 | Full L1 + L2 on-call | Investigation, handover prep |
| NIGHT | 22:00–06:00 | L1 automated + L2 on-call | Monitoring, P1 response only |

### Handover Protocol

```yaml
handover:
  format: structured_yaml
  required_fields:
    - active_incidents:
        - incident_id
        - severity
        - status
        - next_action
        - assigned_to
    - pending_approvals:
        - action_type
        - requested_by
        - timeout
    - sla_status:
        - approaching_breach
        - breached
    - notes:
        - free_text
  delivery:
    - channel: "#soc-handover"
    - format: yaml_block
    - acknowledgment_required: true
  timing:
    handover_prep: "30min before shift end"
    handover_review: "15min before shift end"
    handover_completion: "shift change time"
```

### Shift Handover Example

```yaml
handover:
  from_shift: "DAY"
  to_shift: "EVENING"
  timestamp: "2024-01-15T14:00:00Z"
  active_incidents:
    - incident_id: "inc-2024-01-15-042"
      severity: "HIGH"
      status: "INVESTIGATING"
      next_action: "Awaiting L2 approval for host isolation"
      assigned_to: "john.doe"
  pending_approvals:
    - action_type: "HOST_ISOLATION"
      requested_by: "agent-triage-001"
      timeout: "2024-01-15T14:15:00Z"
  sla_status:
    approaching_breach: []
    breached: []
  notes: "PowerShell alert cluster from 192.168.1.50 — likely lateral movement"
```

---

## 4. Incident Classification

### Severity Mapping

| Severity | MITRE Phase | Business Impact | SLA | Notification |
|---|---|---|---|---|
| CRITICAL | Execution, Exfiltration, Impact | Data breach, ransomware, active compromise | P1 (15min) | Immediate to CISO + Client |
| HIGH | Persistence, Privilege Escalation, Lateral Movement | Confirmed compromise, potential spread | P2 (1hr) | Within 1hr to client |
| MEDIUM | Reconnaissance, Discovery, Credential Access | Suspicious activity, policy violation | P3 (4hr) | Within 24hr to client |
| LOW | Initial Access (blocked), Reconnaissance (limited) | Informational, blocked attempts | P4 (24hr) | Weekly report |

### Classification Logic

```go
// pkg/classification/severity.go
func ClassifyAlert(alert Alert) string {
    score := 0.0

    // MITRE phase weighting
    score += mitrePhaseWeight(alert.MITRETactic)

    // Confidence weighting
    score += alert.Confidence * 2.0

    // Enrichment signals
    if alert.ThreatIntelMatch {
        score += 3.0
    }
    if alert.HistoricalMatch > 2 {
        score += 1.5
    }

    // Asset criticality
    score += assetCriticalityWeight(alert.AssetCriticality)

    switch {
    case score >= 7.0: return "CRITICAL"
    case score >= 5.0: return "HIGH"
    case score >= 3.0: return "MEDIUM"
    default:           return "LOW"
    }
}
```

---

## 5. Communication

### Client Notification Rules

| Event | Notification | Channel | Timing |
|---|---|---|---|
| P1 incident detected | Initial alert | Email + Slack + SMS | Immediate |
| P1 containment executed | Confirmation | Email + Slack | Within 5 min |
| P2 incident detected | Initial alert | Email + Slack | Within 1 hr |
| P1/P2 resolved | Resolution summary | Email | Within 1 hr of resolution |
| Weekly summary | Report | Email | Monday 09:00 |
| Monthly review | Report + meeting | Email + Video call | First Tuesday |
| SLA breach | Alert | PagerDuty + Email | Immediate |
| Platform outage | Status update | Status page + Email | Within 15 min |

### Communication Templates

```yaml
notifications:
  p1_initial:
    subject: "[P1] Active Security Incident — {{.Customer}}"
    body: |
      CRITICAL security incident detected.

      Incident ID: {{.IncidentID}}
      Detected: {{.Timestamp}}
      Severity: CRITICAL
      Summary: {{.Summary}}
      Current Status: {{.Status}}
      Recommended Action: {{.Recommendation}}

      Next update within 30 minutes.
    channels: [email, slack, sms]

  weekly_report:
    subject: "[SOC] Weekly Report — {{.Customer}} — {{.Week}}"
    body: |
      Summary: {{.TotalAlerts}} alerts processed
      P1: {{.P1Count}} | P2: {{.P2Count}} | P3: {{.P3Count}} | P4: {{.P4Count}}
      False Positive Rate: {{.FPRate}}%
      Mean Time to Respond: {{.MTTR}}
      Notable Incidents: {{.NotableSummary}}
    channels: [email]
```

---

## 6. Continuous Improvement

### Post-Incident Review

```
Post-Incident Review Checklist:
├── Timeline reconstruction
│   └── When was the alert generated? When was it triaged? When was it escalated?
├── Detection effectiveness
│   └── Did the agent detect the incident correctly? What was the confidence?
├── Response effectiveness
│   └── Was the containment timely? Were there delays?
├── False positive analysis
│   └── Was this a true positive? If not, what rule change prevents recurrence?
├── Agent performance
│   └── Did the reasoning trace correctly identify the attack pattern?
├── Cost analysis
│   └── What was the LLM cost for this incident? Was it within budget?
└── Action items
    ├── Detection rule tuning
    ├── Prompt adjustments
    ├── Runbook updates
    └── Training data additions
```

### Detection Rule Tuning

```go
// pkg/tuning/rule_optimizer.go
type RuleOptimizer struct {
    alertHistory []Alert
    feedback     []AnalystFeedback
}

func (o *RuleOptimizer) Analyze() []TuningRecommendation {
    var recs []TuningRecommendation

    // Identify rules with high false positive rate
    fpRate := o.calculateFalsePositiveRate()
    for rule, rate := range fpRate {
        if rate > 0.3 {
            recs = append(recs, TuningRecommendation{
                Rule:     rule,
                Issue:    "HIGH_FALSE_POSITIVE_RATE",
                Rate:     rate,
                Action:   "Tighten threshold or add exclusion",
            })
        }
    }

    // Identify rules with low detection rate
    detectionRate := o.calculateDetectionRate()
    for rule, rate := range detectionRate {
        if rate < 0.5 {
            recs = append(recs, TuningRecommendation{
                Rule:     rule,
                Issue:    "LOW_DETECTION_RATE",
                Rate:     rate,
                Action:   "Broaden pattern or add variants",
            })
        }
    }

    return recs
}
```

### Agent Accuracy Tracking

| Metric | Target | Measurement |
|---|---|---|
| Triage Accuracy | >90% | Correct severity classification |
| False Positive Rate | <15% | Alerts dismissed as FP / total alerts |
| Mean Time to Triage | <30 seconds | Time from ingestion to recommendation |
| Mean Time to Contain | <5 minutes | Time from approval to containment execution |
| Escalation Accuracy | >85% | Correctly escalated incidents / total escalations |
| Cost Efficiency | <$0.05/alert | LLM cost per processed alert |

---

## 7. Runbook Philosophy

### Principles

1. **Every failure mode documented** — If it can fail, there is a runbook for it
2. **Every recovery step automated where possible** — Manual steps only when automation is unsafe
3. **Runbooks are tested** — Chaos engineering validates runbook effectiveness
4. **Runbooks are versioned** — Changes tracked in Git with review
5. **Runbooks are accessible** — Available during incidents without authentication barriers

### Runbook Categories

| Category | Examples | Automation Level |
|---|---|---|
| LLM Provider Failure | OpenAI down, Groq rate limited | Fully automated fallback |
| Agent Failure | Agent crash, reasoning timeout | Automated restart + escalation |
| Vector Store Failure | Qdrant unavailable, index corruption | Automated failover |
| Network Partition | Namespace isolation triggered | Automated reconnection |
| Storage Failure | Log storage full, audit chain broken | Automated cleanup + alert |
| Security Breach | Agent compromised, prompt injection | Automated containment + forensic capture |

### Runbook Template

```markdown
# Runbook: {Failure Mode}

## Symptoms
- What operators observe
- Dashboard indicators
- Alert patterns

## Impact
- What is affected
- Which customers impacted
- SLA implications

## Diagnosis
1. Check {specific metric}
2. Query {specific log}
3. Verify {specific component}

## Recovery
### Automated (if available)
```bash
make recover-{component}
```

### Manual (if automated recovery fails)
1. Step one
2. Step two
3. Step three

## Verification
- [ ] Component health check passes
- [ ] Alerts processing normally
- [ ] No data loss confirmed

## Post-Recovery
- Notify affected customers
- Update incident ticket
- Schedule post-incident review
```
