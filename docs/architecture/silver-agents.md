# Silver Agents

## Overview

Silver Agents are automated AI agents that handle alert triage, analysis, and response. Each agent has specific tools and capabilities.

```
+----------------+     +----------------+     +----------------+
|  SILVER TRIAGE |     | SILVER ANALYSIS|     | SILVER RESPONSE|
|                |     |                |     |                |
|  First contact |     | Deep dive      |     | Containment    |
|  Severity assessment | Investigation  |     | Remediation    |
|  Routing       |     | Correlation    |     | Notifications  |
+-------+--------+     +-------+--------+     +-------+--------+
        |                      |                      |
        v                      v                      v
   +---------+           +---------+           +---------+
   | MITRE   |           | OpenCTI |           | N8N     |
   | RAG     |           | GraphQL |           | Workflows|
   +---------+           +---------+           +---------+
   +---------+           +---------+           +---------+
   | Cortex  |           | MISP    |           | Wazuh   |
   | Enrich  |           | Correl  |           | Active  |
   +---------+           +---------+           | Response|
                                               +---------+
                                               +---------+
                                               | Firewall|
                                               | Block   |
                                               +---------+
```

## Silver Triage Agent

First point of contact for all alerts. Performs initial assessment and routing.

### Tools

| Tool | Purpose | MITRE Mapping |
|------|---------|---------------|
| `mitre_rag_search` | Search ATT&CK techniques via RAG | All |
| `cortex_enrich` | Enrich with Cortex analyzers | All |
| `vt_lookup` | VirusTotal IOC lookup | All |

### Usage

```python
from services.langgraph.agents.triage import SilverTriageAgent

agent = SilverTriageAgent()
result = await agent.run({
    "alert_id": "alert-123",
    "alert": {
        "rule_id": 5712,
        "rule_level": 8,
        "source_ip": "203.0.113.45",
    },
    "context": {
        "tenant_id": "acme-corp",
        "semantic": {...},
        "operational": {...},
    },
})

# Result includes:
# - severity: critical/high/medium/low
# - confidence: 0.0-1.0
# - recommended_actions: [...]
# - mitre_mapping: {...}
```

### Severity Mapping

| Rule Level | Severity | Autonomy |
|------------|----------|----------|
| 10-12 | Critical | Requires approval |
| 7-9 | High | Requires approval |
| 4-6 | Medium | Automated |
| 1-3 | Low | Automated |

## Silver Analysis Agent

Deep investigation and correlation of alerts.

### Tools

| Tool | Purpose | MITRE Mapping |
|------|---------|---------------|
| `opencti_query` | Query OpenCTI GraphQL | T1xxx |
| `misp_correlate` | Correlate with MISP events | T1xxx |
| `es_query` | Query Elasticsearch logs | T1xxx |

### Usage

```python
from services.langgraph.agents.analysis import SilverAnalysisAgent

agent = SilverAnalysisAgent()
result = await agent.run({
    "alert_id": "alert-123",
    "alert": {...},
    "context": {...},
})

# Result includes:
# - attack_narrative: "Attacker performed..."
# - related_alerts: [...]
# - iocs: [...]
# - mitre_techniques: [...]
# - confidence: 0.0-1.0
```

## Silver Response Agent

Executes containment and remediation actions.

### Tools

| Tool | Purpose | Approval Required |
|------|---------|-------------------|
| `n8n_execute` | Execute n8n workflow | Depends on action |
| `wazuh_active_response` | Wazuh active response | Yes |
| `firewall_block` | Block IP/port | Yes |
| `slack_notify` | Send Slack notification | No |

### Usage

```python
from services.langgraph.agents.response import SilverResponseAgent

agent = SilverResponseAgent()
result = await agent.run({
    "alert_id": "alert-123",
    "alert": {...},
    "context": {...},
    "approved_actions": ["block_ip", "notify"],
})

# Result includes:
# - actions_taken: [...]
# - actions_pending: [...]  # Needs approval
# - rollback_available: True/False
```

### Approval Flow

```
Response Agent --> Policy Check --> Requires Approval?
                                      |
                    +-----------------+-----------------+
                    |                                   |
                   Yes                                  No
                    |                                   |
                    v                                   v
            +---------------+                 +---------------+
            | Approval Gate |                 | Auto-Execute  |
            |               |                 |               |
            | - Slack msg   |                 | - N8N         |
            | - Teams msg   |                 | - Wazuh       |
            | - HMAC sig    |                 | - Firewall    |
            +-------+-------+                 +---------------+
                    |
                    v
            +---------------+
            | Human Reviews |
            |               |
            | - Approve     |
            | - Reject      |
            | - Timeout     |
            +-------+-------+
                    |
                    v
            +---------------+
            | Execute/Deny  |
            +---------------+
```

## Agent Communication

Agents communicate via LangGraph state:

```python
# State definition
class AgentState(TypedDict):
    alert_id: str
    alert: Dict[str, Any]
    context: Dict[str, Any]
    triage_result: Optional[Dict]
    analysis_result: Optional[Dict]
    response_result: Optional[Dict]
    current_agent: str
    status: str
```

## Configuration

```bash
# Agent settings
GROQ_API_KEY=your-groq-key
OPENAI_API_KEY=your-openai-key

# Tool endpoints
CORTEX_URL=http://cortex:9001/api
OPENCTI_URL=http://opencti:4000/graphql
THEHIVE_URL=http://thehive:9000/api
WAZUH_URL=https://wazuh-manager:55000
N8N_URL=http://n8n:5678
```

## Testing

```bash
# Run all agent tests
python -m pytest tests/unit/agent/ -v

# Run specific agent
python -m pytest tests/unit/agent/test_silver_triage.py -v
python -m pytest tests/unit/agent/test_silver_analysis.py -v
python -m pytest tests/unit/agent/test_silver_response.py -v
```
