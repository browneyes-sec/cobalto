# AI Ethics for SOC Operations

> Ethical principles governing AI agent behavior in the Cobalto Agentic SOC/MDR platform.

---

## 1. Explainability

**Principle:** Every agent decision includes a reasoning trace. Analysts can see exactly why the agent made a recommendation.

**Implementation:**

```go
// internal/agents/reasoning_trace.go
type ReasoningTrace struct {
    AlertID       string             `json:"alert_id"`
    AgentID       string             `json:"agent_id"`
    Confidence    float64            `json:"confidence"`
    Steps         []ReasoningStep    `json:"steps"`
    MITREMapping  []string           `json:"mitre_mapping"`
    EnrichmentSrc []string           `json:"enrichment_sources"`
    FinalDecision string             `json:"final_decision"`
}

type ReasoningStep struct {
    Step        int       `json:"step"`
    Description string    `json:"description"`
    Evidence    string    `json:"evidence"`
    Confidence  float64   `json:"confidence"`
    Timestamp   time.Time `json:"timestamp"`
}
```

**What Analysts See:**
- Step-by-step reasoning from alert ingestion to recommendation
- Which data sources were consulted (enrichment, threat intel, historical alerts)
- Confidence score for each step and overall decision
- MITRE ATT&CK technique mapping with justification
- Raw LLM output alongside structured reasoning

**Guarantee:** No black-box decisions. Every recommendation is traceable to specific evidence.

---

## 2. Human Oversight

**Principle:** All destructive actions require human approval. Escalation on timeout ensures no action is silently dropped.

**Approval Gates:**

| Action Type | Autonomy Level | Timeout | Escalation |
|---|---|---|---|
| Alert Triage | FULL_AUTO | N/A | N/A |
| Enrichment | FULL_AUTO | N/A | N/A |
| Notification (L1) | DRAFT_ONLY | 30 min | L2 Analyst |
| Containment | HUMAN_REQUIRED | 15 min | L3 Analyst |
| Host Isolation | HUMAN_REQUIRED | 10 min | CISO |
| Account Disable | HUMAN_REQUIRED | 5 min | CISO + Client |

**Escalation on Timeout:**
- If no human approves within SLA, action escalates to next tier
- Escalation includes full reasoning trace and original request
- If final tier does not respond, action is queued for next business day with P1 priority
- Never: timeout defaults to "approved"

---

## 3. Bias Mitigation

**Principle:** Diverse training data. Regular model evaluation. Feedback loops to reduce false positives.

**Measures:**

- **Training Data Diversity:** Alert training data sourced from multiple industries, geographies, and attack patterns; not concentrated in any single domain
- **Regular Evaluation:** Monthly model evaluation against held-out test set; metrics tracked: precision, recall, F1, false positive rate per severity level
- **False Positive Feedback Loop:** Analyst feedback on agent recommendations feeds back into evaluation; persistent false positive patterns trigger retraining or prompt adjustment
- **Bias Auditing:** Quarterly review of agent recommendations by severity, source type, and affected system to detect systematic bias
- **Adversarial Testing:** Red team exercises specifically targeting agent decision-making to identify exploitable biases

**Tracking:**
```go
// pkg/ethics/bias_tracking.go
type BiasReport struct {
    Period            string             `json:"period"`
    TotalAlerts       int                `json:"total_alerts"`
    BySeverity        map[string]int     `json:"by_severity"`
    BySource          map[string]int     `json:"by_source"`
    FalsePositiveRate float64            `json:"false_positive_rate"`
    EscalationRate    float64            `json:"escalation_rate"`
    AnalystOverrides  int                `json:"analyst_overrides"`
}
```

---

## 4. Transparency

**Principle:** Agent confidence scores visible. MITRE mapping shown. Enrichment sources disclosed.

**What is Visible to Analysts:**
- Agent confidence score (0.0–1.0) on every recommendation
- MITRE ATT&CK technique and tactic mapping
- All enrichment sources consulted (threat intel feeds, historical alerts, external APIs)
- Model version used for the decision
- Timestamp and latency of the LLM call
- Token consumption for the specific decision

**What is Not Hidden:**
- Model limitations and known failure modes
- Cost of each LLM call
- Alternative recommendations considered
- Areas of uncertainty explicitly flagged

**UI Representation:**
```
Alert: Suspicious PowerShell Execution
├── Agent: Triage Agent v2.3.1
├── Confidence: 0.87
├── Reasoning: [3 steps visible]
├── MITRE: T1059.001 (PowerShell)
├── Enrichment: VirusTotal (clean), Shodan (N/A), Historical (2 similar)
├── Recommendation: Escalate to L2 for investigation
└── Model Cost: $0.003 (1,247 tokens)
```

---

## 5. Accountability

**Principle:** Full audit trail. Who approved what. When actions were taken.

**Accountability Chain:**

```
Alert Ingested (2024-01-15T10:30:00Z)
  → Triage Agent processed (2024-01-15T10:30:12Z, confidence: 0.87)
    → Escalated to L2 Analyst (2024-01-15T10:30:15Z)
      → L2 Analyst: John Doe (john@company.com) approved containment (2024-01-15T10:42:33Z)
        → Response Agent executed containment (2024-01-15T10:42:45Z)
          → Host isolated: 192.168.1.50 (2024-01-15T10:42:47Z)
```

**Audit Log Fields:**
- Timestamp (RFC3339Nano)
- Actor (agent ID or human identity)
- Action performed
- Input data (alert payload)
- Output data (agent recommendation or action result)
- HMAC-SHA256 signature (tamper-evident)

**Retention:** Audit logs retained for 7 years (configurable). Immutable storage. Customer can export at any time.

---

## 6. Rate Limiting

**Principle:** Prevent AI from overwhelming analysts with recommendations.

**Mechanisms:**

- **Alert Deduplication:** Identical alerts within 5-minute window merged; analyst sees one notification, not ten
- **Batch Processing:** Similar alerts grouped for single LLM call; reduces noise and cost
- **Escalation Throttling:** Maximum 5 escalations per hour per analyst; prevents alert fatigue
- **Quiet Hours:** Optional configuration to suppress non-P1 notifications during off-hours
- **Deduplication Window:** Configurable per customer; default 15 minutes for same alert signature

**Configuration:**
```yaml
rate_limiting:
  dedup_window: 15m
  max_escalations_per_hour: 5
  quiet_hours:
    enabled: true
    start: "22:00"
    end: "06:00"
    timezone: "America/New_York"
    exempt_severities: ["CRITICAL"]
```

---

## 7. Graceful Degradation

**Principle:** If the LLM fails, fallback to rule-based triage. Never block on AI.

**Fallback Chain:**

1. **LLM Available:** Agent processes alert with full reasoning, enrichment, and recommendation
2. **LLM Timeout (5s):** Retry once with reduced context window
3. **LLM Unavailable:** Fall back to rule-based triage engine
4. **Rule Engine Unavailable:** Queue alert for manual processing; notify on-call

**Rule-Based Triage:**
```go
// pkg/fallback/rules_engine.go
type RulesEngine struct {
    rules []TriageRule
}

type TriageRule struct {
    Condition  func(alert Alert) bool
    Severity   string
    Action     string
    Confidence float64
}

// Pre-built rules for common scenarios:
// - Known malicious IP → CRITICAL
// - Failed login > 10 in 5min → HIGH
// - New process from temp directory → MEDIUM
// - Standard authentication event → LOW
```

**Guarantee:** The platform never stops processing alerts due to LLM failure. Quality degrades; availability does not.

---

## 8. Model Governance

**Principle:** Version tracking. A/B testing. Rollback capability. Cost caps.

**Model Registry:**

```go
// pkg/models/registry.go
type ModelRegistry struct {
    models map[string]ModelConfig
}

type ModelConfig struct {
    ID            string    `json:"id"`
    Provider      string    `json:"provider"`
    Version       string    `json:"version"`
    CostPer1MTok  float64   `json:"cost_per_1m_tokens"`
    MaxTokens     int       `json:"max_tokens"`
    Enabled       bool      `json:"enabled"`
    DeployedAt    time.Time `json:"deployed_at"`
    RollbackTo    string    `json:"rollback_to,omitempty"`
}
```

**Governance Controls:**
- **Version Tracking:** Every LLM call logged with model ID and version
- **A/B Testing:** Traffic split between model versions; metrics compared before full rollout
- **Rollback:** One-command rollback to previous model version
- **Cost Caps:** Daily and monthly spend limits per model; automatic fallback to cheaper model on breach
- **Evaluation Gates:** New models must pass evaluation suite before production deployment
- **Deprecation Policy:** 30-day notice before model version removal

**Cost Caps Configuration:**
```yaml
model_governance:
  cost_caps:
    daily_limit: 100.00
    monthly_limit: 2500.00
    per_alert_limit: 0.10
  fallback_model: "groq-llama3-8b"
  evaluation:
    required_pass_rate: 0.95
    test_suite: "soc_triage_v2"
```
