# Changelog

All notable changes to the Cobalto platform are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.0] - 2026-06-25

### Added

#### DTP Integration (Detailed Technical Plan)

**Context Engine (5-Layer Model)**
- `frameworks/context-engine/` - New context engineering framework
- Semantic Layer - Business entities (tenant, asset criticality, SLA tier)
- Operational Layer - Current state (alerts, velocity, burst detection)
- Intelligence Layer - Threat intel via RAG (MITRE, OpenCTI)
- Policy Layer - Agent permissions and autonomy levels
- Memory Layer - Prior runs with sliding window summarization
- ContextPackage builder for Silver agents

**Silver Agents (Automated Response)**
- `services/langgraph/agents/triage.py` - Silver Triage Agent
  - MITRE ATT&CK RAG search
  - Cortex enrichment
  - VirusTotal lookup
- `services/langgraph/agents/analysis.py` - Silver Analysis Agent
  - OpenCTI GraphQL queries
  - MISP correlation
  - Elasticsearch queries
- `services/langgraph/agents/response.py` - Silver Response Agent
  - N8N workflow execution
  - Wazuh active response
  - Firewall blocking
  - Slack notifications

**Magenta Supervisor**
- `services/langgraph/agents/supervisor.py` - OSCAR Framework
  - Orient → Strategize → Collect → Analyze → Report
  - Agent routing and orchestration
  - State machine management

**Agent Tools**
- `frameworks/agent-sdk/src/cobalto/agent/triage_tools.py`
- `frameworks/agent-sdk/src/cobalto/agent/analysis_tools.py`
- `frameworks/agent-sdk/src/cobalto/agent/response_tools.py`

**Services**
- `frameworks/agent-sdk/src/cobalto/agent/approval.py` - Human approval gate
  - Slack/Teams integration
  - HMAC signatures
  - Timeout handling
- `frameworks/agent-sdk/src/cobalto/agent/audit.py` - Audit trail
  - HMAC-sealed immutable logs
  - Chain of custody
  - S3 archival
- `frameworks/agent-sdk/src/cobalto/agent/case_service.py` - Case management
  - TheHive integration
  - Auto-create cases
  - SLA tracking

**Playbook Engine**
- `frameworks/soar-sdk/src/cobalto/soar/playbook.py` - Enhanced engine
  - YAML DSL support
  - Version management with history
  - Template engine ({{variable}} substitution)
  - Conditional execution
  - Parallel actions
- `playbooks/` - Sample playbooks
  - `brute-force-response.yaml`
  - `malware-detection-response.yaml`
  - `phishing-response.yaml`

**Webhook Endpoints**
- `POST /webhook/wazuh` - Wazuh alert ingestion
- `POST /webhook/generic` - Generic SIEM webhook
- `POST /webhook/n8n` - n8n callback endpoint
- `WazuhAlert` model with MITRE ATT&CK mapping

**n8n Integration**
- `infra/n8n/workflows/wazuh-cobalt.json` - Wazuh → Cobalt workflow

**Infrastructure (EKS + Terraform)**
- `infra/terraform/modules/namespace-isolation/` - Multi-tenant isolation
  - Network policies (default-deny, allow-dns, allow-same-namespace)
  - Resource quotas per tenant
  - Limit ranges
  - Pod security policies
  - Role bindings
- `infra/terraform/environments/production/` - Production config
  - Multi-tenant namespace setup
  - Enterprise tier configurations
- `infra/kubernetes/charts/cobalto/templates/` - Helm templates
  - `langgraph.yaml` - Deployment, Service, ServiceAccount
  - `n8n.yaml` - Deployment, Service, PVC
  - `secrets.yaml` - Secrets, ExternalSecrets
  - `hpa.yaml` - HPA, PDB
  - `ingress.yaml` - Ingress, ServiceMonitor

**Testing & Validation**
- `tests/atomic_runner.py` - Atomic Red Team test runner
  - 10+ MITRE ATT&CK techniques
  - Synthetic alert generation
  - Coverage tracking
- `tests/load/load_test.py` - Load testing framework
  - Configurable RPS (10K alerts/hour)
  - Concurrent user simulation
  - Burst testing
  - Performance metrics (MTTR, percentiles)
- `tests/test_performance.py` - Performance test suite

### Changed
- Updated `services/langgraph/main.py` with webhook endpoints
- Updated `docker-compose.yml` (removed obsolete version attribute)
- Updated `tests/unit/soar/test_workflow.py` for new Playbook model

### Fixed
- License inconsistency (GPL v3 → MIT)

### Test Coverage
- Context Engine: 11 tests
- Silver Triage: 10 tests
- Silver Analysis: 8 tests
- Silver Response: 8 tests
- Magenta Supervisor: 8 tests
- Approval Service: 4 tests
- Audit Service: 5 tests
- Case Service: 5 tests
- Playbook Engine: 33 tests
- SOAR Workflow: 4 tests
- Atomic Red Team: 14 tests
- Load Testing: 8 tests
- **Total: 206 tests passing**

## [0.1.0] - 2026-06-20

### Added
- Initial project structure
- Core framework (config, logging, metrics, tracing, secrets, health)
- Agent SDK (base agent, state, tools, memory, workflow, supervisor, prompts)
- Intel SDK (GraphQL client, STIX2 mapper, enrichment, MITRE)
- Vector SDK (embedder, retriever, collections)
- MCP Bridge (server, protocol, transport, resources, registry, prompts, middleware, tools)
- SOAR SDK (workflow builder, webhook handler, integrations)
- Testing framework (mock services, fixtures)
- LangGraph Agent Service (FastAPI)
- Docker Compose for local development
- GitHub Actions CI/CD
- Terraform for AWS infrastructure
- Helm chart for Kubernetes
- OpenAPI specification
- Deployment runbook
- Incident response runbook
