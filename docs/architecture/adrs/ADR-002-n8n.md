# ADR-002: n8n over Airflow/Shuffle

## Status

Accepted

## Date

2026-06-25

## Context

Cobalto SOC/MDR needs a workflow orchestration platform to execute security playbooks, automate incident response, and integrate disparate security tools. Requirements include:

- Visual workflow designer for SOC analysts to build and modify playbooks
- Native integrations with security tools (Wazuh, OSINT APIs, cloud providers)
- Webhook-based trigger mechanism for real-time alert processing
- Self-hosted deployment for data sovereignty
- Low-latency execution for time-sensitive response actions
- Non-technical users (SOC analysts) must be able to create workflows

Candidate platforms:

1. **n8n** - Self-hosted workflow automation with visual editor
2. **Apache Airflow** - Data pipeline orchestration (Python-based)
3. **Shuffle** - Security orchestration and automated response (SOAR)

## Decision

We will use **n8n** as the primary workflow orchestration platform.

## Consequences

### Positive

- **Visual editor**: Drag-and-drop interface enables SOC analysts to build playbooks without coding
- **Self-hosted**: Full data sovereignty; no sensitive security data leaves the platform
- **Webhook triggers**: Native webhook support for real-time alert ingestion from Wazuh and LangGraph
- **Integration library**: 400+ built-in integrations including AWS, Azure, HTTP, Slack, email
- **Custom nodes**: Ability to create custom nodes for proprietary security tools
- **Code flexibility**: JavaScript/Python code nodes for complex logic when visual workflows aren't sufficient
- **Active development**: Well-maintained with frequent releases and responsive community

### Negative

- **Not SOAR-native**: Lacks built-in security-specific features like case management, threat intel integration, and SIEM connectors that dedicated SOAR platforms provide
- **Scaling limitations**: May require architecture changes at very high throughput (>10,000 workflows/day)
- **Enterprise features**: Some advanced features (SSO, audit logging) require paid license
- **JavaScript ecosystem**: Node.js runtime may limit some Python-based security tool integrations

### Risks

- Performance at scale may require sharding or queue-based architecture (mitigated by Redis queue backend)
- Security-specific features will need to be built as custom nodes (mitigated by active development)
- Vendor lock-in for workflow definitions (mitigated by JSON export capability)
