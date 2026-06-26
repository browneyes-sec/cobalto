# Architecture Walkthrough for New Developers

## Overview

This document walks through the Cobalto SOC platform architecture, the LangGraph agent service structure, and how to extend the system with new agents and tools.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        External Systems                         │
│  Wazuh (SIEM) │ Slack │ VirusTotal │ Shodan │ MISP │ TheHive   │
└────────┬───────┴───┬───┴─────┬──────┴───┬────┴──┬───┴──────────┘
         │           │         │          │       │
    ┌────▼───────────▼─────────▼──────────▼───────▼────┐
    │              ALB / Ingress Controller             │
    └──────────────────────┬───────────────────────────┘
                           │
    ┌──────────────────────▼───────────────────────────┐
    │                    n8n                            │
    │          Workflow Automation Engine               │
    │    (Webhooks, Triage Routing, Notifications)      │
    └──────────────────────┬───────────────────────────┘
                           │
    ┌──────────────────────▼───────────────────────────┐
    │              LangGraph Agent                      │
    │           AI Analysis Pipeline                    │
    │     (Ingest -> Enrich -> Correlate -> LLM -> Case)│
    └──┬────────┬────────┬────────┬────────┬───────────┘
       │        │        │        │        │
  ┌────▼──┐ ┌──▼───┐ ┌──▼────┐ ┌▼──────┐ ┌▼────────┐
  │Qdrant │ │ Open │ │Cortex │ │  ES   │ │ Postgres │
  │(vector)│ │ CTI  │ │(enrich)│ │(search)│ │  (data) │
  └───────┘ └──────┘ └───────┘ └───────┘ └─────────┘
```

## LangGraph Agent Structure

```
services/langgraph-agent/
├── src/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app entry point
│   ├── config.py                  # Pydantic settings, Vault integration
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alert.py               # AlertPayload, AlertIndicator models
│   │   ├── case.py                # Case, Observable, Timeline models
│   │   └── result.py              # AgentResult, Verdict models
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── state.py               # TypedDict state definition
│   │   ├── workflow.py            # StateGraph definition and compilation
│   │   ├── nodes/
│   │   │   ├── __init__.py
│   │   │   ├── ingest.py          # Alert ingestion and validation
│   │   │   ├── triage.py          # Alert triage decision node
│   │   │   ├── enrich.py          # Observable enrichment
│   │   │   ├── correlate.py       # IOC correlation
│   │   │   ├── llm_analysis.py    # LLM-powered analysis
│   │   │   ├── create_case.py     # TheHive case creation
│   │   │   └── notify.py          # Slack notification
│   │   └── edges/
│   │       ├── __init__.py
│   │       └── conditional.py     # Routing logic between nodes
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── base.py                # BaseTool abstract class
│   │   ├── virustotal.py          # VirusTotal API client
│   │   ├── shodan.py              # Shodan API client
│   │   ├── opencti_client.py      # OpenCTI GraphQL client
│   │   ├── cortex_client.py       # Cortex analyzer client
│   │   ├── qdrant_client.py       # Qdrant vector search
│   │   ├── elasticsearch_client.py # ES search client
│   │   └── thehive_client.py      # TheHive case management
│   ├── services/
│   │   ├── __init__.py
│   │   ├── vault.py               # Vault secrets client
│   │   ├── embedding.py           # OpenAI/local embedding service
│   │   └── metrics.py             # Prometheus metrics
│   └── api/
│       ├── __init__.py
│       ├── routes.py              # FastAPI routes (/analyze, /health, etc.)
│       └── middleware.py          # Auth, request ID, logging middleware
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── test_ingest.py
│   │   ├── test_enrich.py
│   │   └── test_triage.py
│   └── integration/
│       ├── test_workflow.py
│       └── test_api.py
├── alembic/                       # Database migrations
├── pyproject.toml                 # Python project config
├── Dockerfile
└── README.md
```

## Key Entry Points

### `main.py` — Application Bootstrap

```python
# Initializes FastAPI app, mounts routes, configures middleware
# Key components:
# - app = FastAPI(title="Cobalto Agent")
# - Mounts /agent/analyze, /health, /ready, /graph/visualize
# - Configures CORS, request ID middleware, Vault client
# - On startup: initializes Qdrant collections, ES indices, Vault connection
```

### `graph/workflow.py` — Workflow Definition

```python
# Defines the StateGraph:
workflow = StateGraph(AlertState)
workflow.add_node("ingest", ingest_node)
workflow.add_node("triage", triage_node)
workflow.add_node("enrich", enrich_node)
workflow.add_node("correlate", correlate_node)
workflow.add_node("llm_analysis", llm_analysis_node)
workflow.add_node("create_case", create_case_node)
workflow.add_node("notify", notify_node)

# Edges
workflow.add_edge("ingest", "triage")
workflow.add_conditional_edges("triage", route_by_severity)
workflow.add_edge("enrich", "correlate")
workflow.add_edge("correlate", "llm_analysis")
workflow.add_edge("llm_analysis", "create_case")
workflow.add_edge("create_case", "notify")
workflow.add_edge("notify", END)
```

### `graph/state.py` — State Definition

```python
class AlertState(TypedDict):
    alert: AlertPayload
    observables: list[Observable]
    enrichments: dict[str, EnrichmentResult]
    correlations: list[Correlation]
    verdict: str
    confidence: float
    mitre_tactics: list[MitreTactic]
    case_id: str | None
    timeline: list[TimelineEntry]
    errors: list[str]
```

## How the Workflow Executes

1. **Ingest** (`ingest.py`): Validates `AlertPayload`, extracts observables (IPs, hashes, domains)
2. **Triage** (`triage.py`): Routes based on severity and alert type (malware, phishing, brute_force)
3. **Enrich** (`enrich.py`): Calls VirusTotal, Shodan, Cortex analyzers for each observable
4. **Correlate** (`correlate.py`): Searches Qdrant for similar past cases, checks OpenCTI for known IOCs
5. **LLM Analysis** (`llm_analysis.py`): Feeds all context to LLM for verdict, confidence, recommendations
6. **Create Case** (`create_case.py`): Creates TheHive case with observables, timeline, MITRE mappings
7. **Notify** (`notify.py`): Sends Slack notification with case summary and action buttons

## Adding a New Agent Node

1. Create `src/graph/nodes/my_node.py`:

```python
from src.graph.state import AlertState

async def my_node(state: AlertState) -> dict:
    """Description of what this node does."""
    # Access state
    alert = state["alert"]
    observables = state["observables"]

    # Do work
    result = await some_api_call(observables)

    # Return state updates
    return {"enrichments": {**state.get("enrichments", {}), "my_source": result}}
```

2. Register in `src/graph/workflow.py`:

```python
from src.graph.nodes.my_node import my_node

workflow.add_node("my_node", my_node)
```

3. Add edge(s):

```python
# Sequential
workflow.add_edge("previous_node", "my_node")

# Conditional
workflow.add_conditional_edges("my_node", my_routing_function)
```

4. Update `src/graph/state.py` if new state fields are needed.

## Adding a New Tool

1. Create `src/tools/my_tool.py`:

```python
from src.tools.base import BaseTool
from src.config import settings
from src.services.vault import vault_client

class MyTool(BaseTool):
    name: str = "my_tool"
    description: str = "What this tool does"

    async def execute(self, **kwargs) -> dict:
        # Get API key from Vault
        api_key = await vault_client.get_secret("secret/cobalto/tools/my-tool")

        # Call external API
        response = await self.http_client.get(
            "https://api.example.com/v1/lookup",
            params={"query": kwargs["query"]},
            headers={"Authorization": f"Bearer {api_key}"}
        )
        return response.json()

my_tool = MyTool()
```

2. Register in the node that uses it:

```python
from src.tools.my_tool import my_tool

async def enrich_node(state: AlertState) -> dict:
    results = {}
    for observable in state["observables"]:
        results[observable.value] = await my_tool.execute(query=observable.value)
    return {"enrichments": results}
```

## Adding a New Tool to LangChain (LLM)

If the LLM needs to call the tool autonomously during analysis:

```python
from langchain_core.tools import tool

@tool
def lookup_ioc(ioc_value: str, ioc_type: str) -> str:
    """Look up an IOC in threat intelligence sources."""
    # Implementation
    return json.dumps(results)

# Add to agent in llm_analysis_node.py
agent = create_react_agent(
    model=llm,
    tools=[lookup_ioc, other_tool],
    state_modifier="You are a SOC analyst..."
)
```

## Modifying the Workflow Graph

### Adding a Branch

```python
def route_by_triage(state: AlertState) -> str:
    severity = state["alert"]["severity"]
    if severity == "critical":
        return "immediate_response"
    elif severity == "high":
        return "enrich"
    else:
        return "queue_for_review"

workflow.add_conditional_edges("triage", route_by_triage)
```

### Adding a Loop (Retry/Re-enrich)

```python
def should_retry_enrichment(state: AlertState) -> str:
    failed = [e for e in state.get("errors", []) if "enrich" in e]
    if failed and state.get("retry_count", 0) < 3:
        return "enrich"
    return "continue"

workflow.add_conditional_edges("enrich", should_retry_enrichment)
```

### Adding Parallel Execution

```python
from langgraph.graph import END

workflow.add_node("enrich_vt", enrich_virustotal)
workflow.add_node("enrich_shodan", enrich_shodan)
workflow.add_node("enrich_cortex", enrich_cortex)

# Fan out
workflow.add_edge("triage", "enrich_vt")
workflow.add_edge("triage", "enrich_shodan")
workflow.add_edge("triage", "enrich_cortex")

# Fan in with custom node
workflow.add_node("merge_enrichments", merge_results)
workflow.add_edge("enrich_vt", "merge_enrichments")
workflow.add_edge("enrich_shodan", "merge_enrichments")
workflow.add_edge("enrich_cortex", "merge_enrichments")
```

## Debugging

### Local Trace Visualization

```python
from langgraph.graph import StateGraph

# Enable tracing
config = {"recursion_limit": 50}
result = await workflow.ainvoke(initial_state, config=config)

# Print state at each step
for step in result.get("timeline", []):
    print(f"  {step['step']}: {step['status']} ({step['duration_ms']}ms)")
```

### LangSmith Integration

```bash
export LANGCHAIN_TRACING_V2=true
export LANGCHAIN_API_KEY=your-key
export LANGCHAIN_PROJECT=cobalto-soc
```

### Testing a Single Node

```python
import pytest

async def test_enrich_node():
    state = {
        "alert": {"alert_id": "test-001", "indicators": [{"type": "ip", "value": "1.2.3.4"}]},
        "observables": [{"type": "ip", "value": "1.2.3.4"}],
        "enrichments": {},
        "errors": [],
    }
    result = await enrich_node(state)
    assert "enrichments" in result
    assert "virustotal" in result["enrichments"]
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| TypedDict for state | Type safety without Pydantic overhead in graph |
| Async everywhere | Non-blocking I/O for API calls and DB operations |
| Vault for all secrets | Centralized rotation, audit logging, dynamic credentials |
| Qdrant for vectors | Performance at scale, filtering, native K8s deployment |
| LangGraph over raw LangChain | State machine visualization, checkpointing, human-in-the-loop |
| n8n for orchestration | Visual workflow builder for SOC analysts, no-code alert routing |
