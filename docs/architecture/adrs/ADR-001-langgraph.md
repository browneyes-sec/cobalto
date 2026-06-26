# ADR-001: LangGraph over CrewAI/AutoGen

## Status

Accepted

## Date

2026-06-25

## Context

Cobalto SOC/MDR requires an AI agent framework to power automated alert triage, investigation, and response orchestration. The agent must:

- Handle complex multi-step reasoning for alert analysis
- Integrate with external tools (SIEM APIs, threat intelligence platforms, response systems)
- Maintain conversational context across investigation sessions
- Support human-in-the-loop workflows for analyst oversight
- Scale to process hundreds of alerts concurrently
- Provide visibility into agent reasoning for audit and compliance

Three candidate frameworks were evaluated:

1. **LangGraph** (LangChain ecosystem) - Graph-based agent orchestration
2. **CrewAI** - Multi-agent collaboration framework
3. **AutoGen** (Microsoft) - Multi-agent conversation framework

## Decision

We will use **LangGraph** as the primary AI agent framework for the Cobalto platform.

## Consequences

### Positive

- **State management**: LangGraph's graph-based state machine provides explicit control flow, which is critical for audit trails and deterministic investigation paths
- **Tool integration**: Native integration with LangChain tool ecosystem allows rapid addition of SIEM, threat intel, and response tools
- **Human-in-the-loop**: Built-in checkpointing and interrupt mechanisms enable analyst review at key decision points
- **Observability**: Graph structure enables tracing and visualization of agent reasoning for SOC analysts
- **Scalability**: Async execution and state persistence support high-throughput alert processing
- **Ecosystem**: Active development, strong community, and extensive documentation

### Negative

- **Complexity**: Graph-based API has a steeper learning curve than simpler agent frameworks
- **Vendor coupling**: Tight integration with LangChain ecosystem may limit future flexibility
- **Immaturity**: Relatively newer than CrewAI; some advanced features may be experimental
- **LLM dependency**: Agent effectiveness heavily dependent on LLM quality and prompt engineering

### Risks

- LLM hallucination during investigation could produce false conclusions (mitigated by human-in-the-loop)
- Framework evolution may require refactoring as LangGraph matures
- Token costs at scale may be significant (mitigated by intelligent routing and caching)
