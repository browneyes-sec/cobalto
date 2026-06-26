# LangGraph Agent Service Architecture

## Service Overview

The LangGraph Agent Service is the cognitive core of the Cobalto platform. It is a Python 3.11+ FastAPI application that orchestrates multi-agent SOC workflows using LangGraph state machines. Each alert triggers a deterministic graph execution that moves from initial triage through analysis, enrichment, response planning, human approval, and final documentation.

The service exposes a synchronous `POST /agent/analyze` endpoint consumed by n8n automation workflows and an async WebSocket endpoint for real-time streaming of agent progress to the Cobalt Console.

**Key characteristics:**
- Stateful graph execution with checkpointing to PostgreSQL
- Deterministic node ordering with conditional branching
- Tool-permission scoping per agent node
- HMAC-signed execution receipts for every tool call
- Full audit trail persisted to Elasticsearch

## Graph Topology

The agent graph contains **7 nodes** and **2 conditional edges**. The topology encodes the operational SOP for incident handling.

```mermaid
graph TD
    START([Trigger]) --> TRIAGE[triage]
    TRIAGE --> ANALYSIS[analysis]
    ANALYSIS --> THREAT_INTEL[threat_intel]
    THREAT_INTEL --> DECISION{fp_probability > 0.85?}
    DECISION -- Yes --> DOCUMENTATION[documentation]
    DECISION -- No --> RESPONSE[response]
    RESPONSE --> HUMAN_GATE{human_approved?}
    HUMAN_GATE -- Approved --> DOCUMENTATION
    HUMAN_GATE -- Timeout / Rejected --> ESCALATE[escalate]
    ESCALATE --> DOCUMENTATION
    DOCUMENTATION --> END([Complete])
```

### Node Execution Order

| Order | Node | Type | Conditional Source |
|-------|------|------|--------------------|
| 1 | `triage` | Agent | — |
| 2 | `analysis` | Agent | — |
| 3 | `threat_intel` | Agent | — |
| 4 | `response` | Agent | `fp_probability ≤ 0.85` |
| 5 | `human_gate` | Agent | `fp_probability ≤ 0.85` |
| 6 | `escalate` | Agent | `human_approved == False` |
| 7 | `documentation` | Agent | Always (terminal) |

### Conditional Edges

1. **`threat_intel → decision`**: Routes to `documentation` (false positive) or `response` (true positive) based on `false_positive_probability` threshold of 0.85.
2. **`human_gate → decision`**: Routes to `documentation` on approval or `escalate` on timeout/rejection.

## Agent State Schema

The `SOCAgentState` TypedDict is the single source of truth passed through every node. Each node reads from and writes to this shared state.

```python
from typing import TypedDict, Literal
from pydantic import BaseModel

class SOCAgentState(TypedDict):
    # --- Input ---
    alert: dict                          # Raw alert payload from Wazuh/n8n
    severity: Literal["P1","P2","P3","P4"]

    # --- Triage Output ---
    false_positive_probability: float    # 0.0–1.0, ML-scored FP likelihood
    mitre_techniques: list[str]          # MITRE ATT&CK technique IDs (e.g. T1059.001)
    attack_narrative: str                # Human-readable kill-chain summary

    # --- Analysis Output ---
    affected_assets: list[dict]          # Hosts, users, IPs impacted
    threat_actor_matches: list[dict]     # Threat actor profiles from OpenCTI
    ioc_enrichment: dict                 # Enriched IOCs from Cortex (VirusTotal, etc.)

    # --- Response Output ---
    response_actions: list[dict]         # Containment/isolation actions taken

    # --- Human Gate ---
    human_approved: bool | None          # True/False/None (timeout)
    approval_timeout: bool               # True if gate timed out (15 min)

    # --- Documentation ---
    incident_id: str                     # Generated incident UUID
    final_report: str                    # Markdown incident report
    messages: list[dict]                 # Full agent message history
```

### State Field Reference

| Field | Type | Mutated By | Description |
|-------|------|-----------|-------------|
| `alert` | `dict` | Input | Raw alert payload, immutable after ingestion |
| `severity` | `str` | `triage` | Priority level assigned during triage |
| `false_positive_probability` | `float` | `triage` | ML-scored probability that alert is false positive |
| `mitre_techniques` | `list[str]` | `triage`, `analysis` | ATT&CK technique IDs identified |
| `attack_narrative` | `str` | `analysis` | Narrative description of the attack chain |
| `affected_assets` | `list[dict]` | `analysis` | Asset inventory impact list |
| `threat_actor_matches` | `list[dict]` | `threat_intel` | Matched threat actor profiles |
| `ioc_enrichment` | `dict` | `threat_intel` | Enriched IOC data from Cortex |
| `response_actions` | `list[dict]` | `response` | Actions taken or recommended |
| `human_approved` | `bool \| None` | `human_gate` | Approval decision |
| `approval_timeout` | `bool` | `human_gate` | Whether approval window expired |
| `incident_id` | `str` | `documentation` | Generated incident identifier |
| `final_report` | `str` | `documentation` | Assembled markdown report |
| `messages` | `list[dict]` | All nodes | Cumulative agent message log |

## Agent Implementations

### Triage Agent

**Purpose:** Initial alert classification and false-positive scoring.

**Logic:**
1. Parses the raw alert payload to extract source IP, destination IP, affected host, rule ID, and timestamp.
2. Queries Qdrant for historically similar alerts using the alert signature as an embedding.
3. Computes `false_positive_probability` using a gradient-boosted classifier trained on labeled alerts.
4. Maps detected signatures to MITRE ATT&CK technique IDs.
5. Assigns severity level based on CVSS score, asset criticality, and FP probability.

**State mutations:** `severity`, `false_positive_probability`, `mitre_techniques`

### Analysis Agent

**Purpose:** Deep-dive into alert context and impact assessment.

**Logic:**
1. Enriches affected assets by querying the CMDB for host criticality, OS, and owning team.
2. Correlates the alert with related alerts in the same time window (±30 minutes).
3. Builds the `attack_narrative` by sequencing correlated events into a kill-chain story.
4. Updates `mitre_techniques` with additional techniques discovered during correlation.

**State mutations:** `attack_narrative`, `affected_assets`, `mitre_techniques`

### Threat Intel Agent

**Purpose:** External threat intelligence correlation.

**Logic:**
1. Queries OpenCTI GraphQL API for threat actor profiles matching observed TTPs and IOCs.
2. Retrieves STIX pattern matches for IP addresses, domains, and file hashes.
3. Enriches IOCs through Cortex (VirusTotal, AbuseIPDB, Shodan) for reputation scoring.
4. Updates `false_positive_probability` downward if high-confidence threat actor matches exist.

**State mutations:** `threat_actor_matches`, `ioc_enrichment`, `false_positive_probability`

### Response Agent

**Purpose:** Containment action planning and execution.

**Logic:**
1. Evaluates the severity and impact to determine required containment level.
2. Generates a response plan: host isolation, credential reset, firewall rule creation, or process termination.
3. Executes approved actions via Wazuh active response API or TheHive case creation.
4. Records all actions taken in `response_actions` with timestamps and outcomes.

**State mutations:** `response_actions`

### Human Gate Agent

**Purpose:** Mandatory human-in-the-loop approval checkpoint.

**Logic:**
1. Sends an approval request to the assigned analyst via Slack with an `ApprovalDialog` component.
2. Starts a 15-minute countdown timer.
3. If approved before timeout: sets `human_approved = True`.
4. If timeout expires: sets `approval_timeout = True`, `human_approved = False`.
5. If rejected: sets `human_approved = False`.

**State mutations:** `human_approved`, `approval_timeout`

### Documentation Agent

**Purpose:** Incident report assembly and case creation.

**Logic:**
1. Assembles the `final_report` from all accumulated state fields using a Jinja2 template.
2. Creates a case in TheHive with the full report attached.
3. Generates the `incident_id` (UUID v4).
4. Persists the complete state to PostgreSQL for audit and search.

**State mutations:** `incident_id`, `final_report`

### Escalate Agent

**Purpose:** Handle cases where human approval was denied or timed out.

**Logic:**
1. Escalates the alert to the on-call security lead via PagerDuty integration.
2. Creates a high-priority TheHive case tagged with `escalation_reason`.
3. Appends escalation context to `response_actions`.
4. Routes to `documentation` for final report generation.

**State mutations:** `response_actions`

## Tool Integration

### mitre_attack_search (Qdrant)

Vector search against the MITRE ATT&CK knowledge base stored in Qdrant.

- **Collection:** `mitre_techniques`
- **Embedding model:** `text-embedding-3-small` (OpenAI)
- **Query:** Alert signature text → top-5 matching techniques
- **Returns:** Technique ID, name, description, platforms, detection recommendations

### enrich_ioc (Cortex)

IOC enrichment via Cortex analyzer connectors.

- **Supported IOCs:** IP addresses, domains, URLs, file hashes (MD5, SHA1, SHA256)
- **Analyzers:** VirusTotal, AbuseIPDB, Shodan, MaxMind GeoIP
- **Output:** Reputation score, geolocation, ASN, known malware associations, WHOIS data
- **Timeout:** 30 seconds per analyzer, with circuit-breaker fallback

### opencti_query (OpenCTI GraphQL)

Threat intelligence queries against the OpenCTI platform.

- **Endpoint:** `https://opencti.internal:4000/graphql`
- **Authentication:** Bearer token (Vault-managed)
- **Queries:**
  - `threatActors(filter: { techniques: [...] })` — Match actors by TTPs
  - `indicators(filter: { pattern: "..." })` — STIX indicator lookup
  - `reports(filter: { relatedTo: "..." })` — Contextual threat reports
- **Rate limit:** 100 requests/minute

## Middleware Stack

| Middleware | Purpose | Configuration |
|-----------|---------|---------------|
| `RateLimiter` | Per-IP rate limiting using token bucket | 100 req/min default, configurable per endpoint |
| `AuditLogger` | Logs every request/response to Elasticsearch | Index: `agent-audit-{YYYY.MM}`, includes request hash |
| `InputValidator` | Pydantic model validation on all inputs | Strict mode, rejects unknown fields |
| `PromptInjectionGuard` | Detects and blocks prompt injection attempts | Regex + ML classifier, blocks on confidence > 0.9 |

### PromptInjectionGuard Details

The guard operates in two layers:

1. **Regex layer:** Scans for known injection patterns (`ignore previous`, `system:`, `<|im_start|>`, etc.).
2. **ML layer:** Fine-tuned DistilBERT classifier trained on prompt injection datasets (74k samples).

Blocked requests return HTTP 422 with a sanitized error message. All blocked attempts are logged to the audit trail with full request context.

## Configuration

Configuration is managed via Pydantic `BaseSettings` with environment variable overrides.

```python
class AgentConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="COBALT_AGENT_")

    # Graph
    max_iterations: int = 20
    checkpoint_interval: int = 1
    fp_threshold: float = 0.85

    # LLM
    llm_provider: str = "openai"
    llm_model: str = "gpt-4o"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096

    # Tools
    qdrant_url: str = "http://qdrant:6333"
    qdrant_collection: str = "mitre_techniques"
    cortex_url: str = "http://cortex:9001"
    cortex_timeout: int = 30
    opencti_url: str = "http://opencti:4000"
    opencti_timeout: int = 15

    # Human Gate
    approval_timeout_minutes: int = 15
    slack_webhook_url: str = ""

    # Middleware
    rate_limit_per_minute: int = 100
    audit_index_prefix: str = "agent-audit"
    prompt_injection_threshold: float = 0.9

    # Storage
    postgres_dsn: str = "postgresql://cobalt:secret@postgres:5432/cobalt_agent"
    redis_url: str = "redis://redis:6379/0"
    elasticsearch_url: str = "http://elasticsearch:9200"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `COBALT_AGENT_MAX_ITERATIONS` | `20` | Maximum graph node executions per run |
| `COBALT_AGENT_FP_THRESHOLD` | `0.85` | False-positive probability threshold for early exit |
| `COBALT_AGENT_LLM_MODEL` | `gpt-4o` | LLM model for agent reasoning |
| `COBALT_AGENT_QDRANT_URL` | `http://qdrant:6333` | Qdrant vector database endpoint |
| `COBALT_AGENT_CORTEX_URL` | `http://cortex:9001` | Cortex analyzer endpoint |
| `COBALT_AGENT_OPENCTI_URL` | `http://opencti:4000` | OpenCTI GraphQL endpoint |
| `COBALT_AGENT_APPROVAL_TIMEOUT_MINUTES` | `15` | Human gate timeout |
| `COBALT_AGENT_POSTGRES_DSN` | — | PostgreSQL connection string |

## Mermaid Diagrams

### Agent Workflow

```mermaid
flowchart LR
    subgraph Ingestion
        A[n8n Webhook] -->|POST /agent/analyze| B[FastAPI Router]
    end

    subgraph Middleware
        B --> C[InputValidator]
        C --> D[RateLimiter]
        D --> E[PromptInjectionGuard]
        E --> F[AuditLogger]
    end

    subgraph Graph
        F --> G[LangGraph Runner]
        G --> H[triage]
        H --> I[analysis]
        I --> J[threat_intel]
        J --> K{decision}
        K -->|FP > 0.85| L[documentation]
        K -->|TP| M[response]
        M --> N[human_gate]
        N -->|approved| L
        N -->|timeout| O[escalate]
        O --> L
    end

    subgraph Tools
        H -.->|vector search| P[Qdrant]
        I -.->|CMDB lookup| Q[PostgreSQL]
        J -.->|STIX query| R[OpenCTI]
        J -.->|IOC enrichment| S[Cortex]
        M -.->|active response| T[Wazuh]
        M -.->|case creation| U[TheHive]
    end

    L -->|WebSocket| V[Cobalt Console]
    L -->|persist| W[Elasticsearch]
```

### State Mutation Table

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#1e293b', 'secondaryColor': '#334155'}}}%%
graph TD
    subgraph "State Mutations per Node"
        direction LR
        T["triage<br/>severity ✓<br/>fp_probability ✓<br/>mitre_techniques ✓"]
        A["analysis<br/>attack_narrative ✓<br/>affected_assets ✓<br/>mitre_techniques ✓"]
        TI["threat_intel<br/>threat_actor_matches ✓<br/>ioc_enrichment ✓<br/>fp_probability ✓"]
        R["response<br/>response_actions ✓"]
        HG["human_gate<br/>human_approved ✓<br/>approval_timeout ✓"]
        E["escalate<br/>response_actions ✓"]
        D["documentation<br/>incident_id ✓<br/>final_report ✓"]
    end
```

### Tool Call Flow

```mermaid
sequenceDiagram
    participant n8n as n8n
    participant API as FastAPI
    participant LG as LangGraph
    participant QR as Qdrant
    participant OC as OpenCTI
    participant CX as Cortex
    participant WZ as Wazuh
    participant TH as TheHive

    n8n->>API: POST /agent/analyze (alert payload)
    API->>LG: Execute graph (SOCAgentState)

    rect rgb(30, 41, 59)
        Note over LG: triage node
        LG->>QR: Search similar alerts
        QR-->>LG: Top-5 matches
        LG->>LG: Compute FP probability
    end

    rect rgb(30, 41, 59)
        Note over LG: analysis node
        LG->>LG: Correlate related alerts
        LG->>LG: Build attack narrative
    end

    rect rgb(30, 41, 59)
        Note over LG: threat_intel node
        LG->>OC: Query threat actors (GraphQL)
        OC-->>LG: Actor profiles
        LG->>CX: Enrich IOCs (VirusTotal)
        CX-->>LG: Reputation data
    end

    alt TP (fp_probability ≤ 0.85)
        rect rgb(30, 41, 59)
            Note over LG: response node
            LG->>WZ: Active response commands
            LG->>TH: Create case
        end
        rect rgb(30, 41, 59)
            Note over LG: human_gate node
            LG->>n8n: Send approval request
            n8n-->>LG: Approved/Timeout
        end
    else FP (fp_probability > 0.85)
        Note over LG: Skip to documentation
    end

    rect rgb(30, 41, 59)
        Note over LG: documentation node
        LG->>TH: Update case with report
        LG-->>API: Final SOCAgentState
    end

    API-->>n8n: AgentResult (incident_id, report)
```
