# Cost Governance Framework

> Financial controls for LLM operations in the Cobalto Agentic SOC/MDR platform.

---

## 1. LLM Cost Model

### Pricing Reference

| Provider | Model | Input ($/1M tokens) | Output ($/1M tokens) | Free Tier | Use Case |
|---|---|---|---|---|---|
| OpenAI | GPT-4o | $2.50 | $10.00 | No | Complex analysis, multi-step reasoning |
| OpenAI | GPT-4o-mini | $0.15 | $0.60 | No | Simple triage, enrichment summaries |
| Groq | Llama3-8B-8192 | $0.00 | $0.00 | Yes (30K RPM) | Triage, classification, simple extraction |
| Groq | Mixtral-8x7B-32768 | $0.00 | $0.00 | Yes (30K RPM) | Medium complexity, threat intel lookup |
| Local | Llama3-8B (Ollama) | $0.00 | $0.00 | Unlimited | Offline mode, air-gapped deployments |

### Cost Allocation by Agent

| Agent | Model | Avg Tokens/Call | Cost/Call | Monthly (50K alerts) |
|---|---|---|---|---|
| Triage | Groq Llama3-8B | 1,200 | $0.00 | $0.00 |
| Enrichment | Groq Mixtral | 1,800 | $0.00 | $0.00 |
| Analysis | GPT-4o | 3,200 | $0.012 | $600.00 |
| Threat Intel | GPT-4o-mini | 2,000 | $0.002 | $100.00 |
| Response | GPT-4o | 1,500 | $0.006 | $300.00 |
| **Total** | | | **$0.020** | **$1,000.00** |

---

## 2. Token Budget Per Agent

### Budget Allocation

| Agent | Max Input Tokens | Max Output Tokens | Max Tokens/Call | Burst Limit |
|---|---|---|---|---|
| Triage | 1,500 | 500 | 2,000 | 3,000 |
| Enrichment | 2,000 | 1,000 | 3,000 | 4,500 |
| Analysis | 3,000 | 1,000 | 4,000 | 6,000 |
| Threat Intel | 2,000 | 1,000 | 3,000 | 4,500 |
| Response | 1,500 | 500 | 2,000 | 3,000 |

### Budget Enforcement

```go
// pkg/llm/token_budget.go
type TokenBudget struct {
    AgentID       string `json:"agent_id"`
    MaxInput      int    `json:"max_input"`
    MaxOutput     int    `json:"max_output"`
    MaxTotal      int    `json:"max_total"`
    Used          int    `json:"used"`
    Period        string `json:"period"` // "daily", "monthly"
    DailyLimit    int    `json:"daily_limit"`
    MonthlyLimit  int    `json:"monthly_limit"`
}

func (b *TokenBudget) CanProcess(inputTokens int) bool {
    projected := b.Used + inputTokens
    return projected <= b.DailyLimit && inputTokens <= b.MaxInput
}
```

---

## 3. Monthly Cost Estimation

### Scenario: 50,000 Alerts/Month

| Component | Volume | Unit Cost | Monthly Cost |
|---|---|---|---|
| **LLM - Triage** | 50K calls | $0.00 (Groq) | $0.00 |
| **LLM - Enrichment** | 50K calls | $0.00 (Groq) | $0.00 |
| **LLM - Analysis** | 15K calls (30%) | $0.012 | $180.00 |
| **LLM - Threat Intel** | 50K calls | $0.002 | $100.00 |
| **LLM - Response** | 10K calls (20%) | $0.006 | $60.00 |
| **Embedding** | 50K alerts + 100K enrichments | $0.0001 | $15.00 |
| **Qdrant Storage** | 150K vectors | $0.00 | $0.00 (self-hosted) |
| **Kubernetes** | 3-node cluster | $0.45/hr | $324.00 |
| **Storage (S3)** | 500GB logs | $0.023/GB | $11.50 |
| **Network** | 1TB transfer | $0.09/GB | $90.00 |
| **Total** | | | **$780.50** |

### Scaling Projections

| Monthly Alerts | LLM Cost | Infrastructure | Total |
|---|---|---|---|
| 10K | $70.00 | $425.50 | $495.50 |
| 50K | $355.00 | $425.50 | $780.50 |
| 100K | $710.00 | $650.00 | $1,360.00 |
| 500K | $3,550.00 | $2,400.00 | $5,950.00 |
| 1M | $7,100.00 | $4,500.00 | $11,600.00 |

---

## 4. Cost Monitoring

### Grafana Dashboard

```
Dashboard: SOC Platform Cost Overview
├── Panel: Daily LLM Spend (line chart)
│   └── Breakdown by agent: triage, enrichment, analysis, threat_intel, response
├── Panel: Token Consumption (bar chart)
│   └── Input vs Output tokens per agent per day
├── Panel: Model Cost Distribution (pie chart)
│   └── GPT-4o vs GPT-4o-mini vs Groq vs Local
├── Panel: Budget Utilization (gauge)
│   └── Current spend vs daily/monthly budget per agent
├── Panel: Cost per Alert (stat)
│   └── Rolling 7-day average cost per processed alert
└── Panel: Anomaly Detection (time series)
    └── Unusual cost spikes highlighted with alert correlation
```

### Metrics Collected

```go
// pkg/observability/cost_metrics.go
var (
    llmTokensUsed = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cobalto_llm_tokens_total",
            Help: "Total LLM tokens consumed",
        },
        []string{"agent", "model", "type"}, // type: input/output
    )

    llmCostDollars = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "cobalto_llm_cost_dollars_total",
            Help: "Total LLM cost in USD",
        },
        []string{"agent", "model"},
    )

    alertProcessingCost = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "cobalto_alert_processing_cost_dollars",
            Help:    "Cost per alert processed",
            Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0},
        },
        []string{"agent"},
    )
)
```

---

## 5. Optimization Strategies

### Embedding Caching

```go
// pkg/rag/embedding_cache.go
type EmbeddingCache struct {
    qdrant  *qdrant.Client
    ttl     time.Duration
    hitCount prometheus.Counter
    missCount prometheus.Counter
}

func (c *EmbeddingCache) Get(text string) ([]float32, bool) {
    hash := sha256.Sum256([]byte(text))
    vector, err := c.qdrant.Get(hash[:])
    if err == nil {
        c.hitCount.Inc()
        return vector, true
    }
    c.missCount.Inc()
    return nil, false
}
```

**Cache Performance:**
- Alert descriptions: 82% hit rate (many alerts share similar descriptions)
- Enrichment summaries: 76% hit rate (common threat intel lookups)
- Historical context: 91% hit rate (repeated references to known IOCs)

### Batch Processing

```go
// pkg/batch/processor.go
type BatchProcessor struct {
    maxBatchSize int
    maxWait      time.Duration
    flushChan    chan struct{}
}

// Alerts within the same window with similar characteristics are batched:
// - Same source IP → single enrichment call
// - Same MITRE technique → single analysis call
// - Same affected host → single response plan
```

### Model Selection Strategy

```
Decision Tree for Model Selection:
├── Is this a simple classification (alert/no-alert)?
│   └── Yes → Groq Llama3-8B (free)
├── Does this require multi-step reasoning?
│   └── Yes → GPT-4o ($2.50/$10.00 per 1M tokens)
├── Is this a summary or extraction?
│   └── Yes → GPT-4o-mini ($0.15/$0.60 per 1M tokens)
├── Is this an air-gapped deployment?
│   └── Yes → Local Llama3-8B (free)
└── Default → Groq first, escalate to GPT-4o if confidence < 0.7
```

---

## 6. Budget Alerts

### Alert Thresholds

| Metric | Warning | Critical | Action |
|---|---|---|---|
| Daily LLM spend | >$80 | >$120 | Slack notification |
| Monthly LLM spend | >$2,000 | >$3,000 | Email to finance + CISO |
| Per-agent daily tokens | >80% budget | >95% budget | Throttle non-essential agents |
| Cost per alert | >$0.05 | >$0.10 | Review model selection |
| Embedding cache hit rate | <70% | <50% | Investigate cache invalidation |

### Notification Configuration

```yaml
cost_alerts:
  slack:
    webhook: "${SLACK_COST_WEBHOOK}"
    channel: "#soc-cost-alerts"
    thresholds:
      daily_spend_warning: 80.00
      daily_spend_critical: 120.00
      monthly_spend_warning: 2000.00
      monthly_spend_critical: 3000.00
  email:
    recipients:
      - finance@company.com
      - ciso@company.com
    frequency: weekly
  pagerduty:
    enabled: true
    service_key: "${PAGERDUTY_COST_KEY}"
    trigger_on: monthly_spend_critical
```

---

## 7. Cost Allocation

### Per-Customer Tracking

```go
// pkg/billing/customer_cost.go
type CustomerCost struct {
    CustomerID     string    `json:"customer_id"`
    Period         string    `json:"period"` // "2024-01"
    AlertCount     int       `json:"alert_count"`
    LLMCost        float64   `json:"llm_cost"`
    InfraCost      float64   `json:"infra_cost"`
    StorageCost    float64   `json:"storage_cost"`
    TotalCost      float64   `json:"total_cost"`
    CostPerAlert   float64   `json:"cost_per_alert"`
    BudgetUsed     float64   `json:"budget_used_pct"`
}
```

### MDR Billing Model

| Tier | Monthly Alerts | Included | Overage Rate |
|---|---|---|---|
| Starter | 5,000 | $500 | $0.10/alert |
| Professional | 25,000 | $1,800 | $0.08/alert |
| Enterprise | 100,000 | $5,500 | $0.06/alert |
| Unlimited | Unlimited | $12,000 | N/A |

### Cost Report Template

```markdown
## Monthly Cost Report — {Customer} — {Month}

### Summary
- Total alerts processed: {count}
- Total LLM cost: ${amount}
- Total infrastructure cost: ${amount}
- Cost per alert: ${amount}
- Budget utilization: {percentage}%

### Breakdown by Agent
| Agent | Calls | Tokens | Cost |
|---|---|---|---|
| Triage | {count} | {tokens} | $0.00 |
| Analysis | {count} | {tokens} | ${amount} |
| ... | | | |

### Optimization Recommendations
1. {recommendation}
2. {recommendation}
```
