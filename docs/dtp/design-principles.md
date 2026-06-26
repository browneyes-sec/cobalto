# Core Design Technology Principles

> 10 axioms governing architecture, code, and operational decisions in the Cobalto Agentic SOC/MDR platform.

---

## 1. AI-Augmented, Not AI-Replaced

**Definition:** AI agents assist human analysts by triaging, correlating, enriching, and drafting responses. They never replace human judgment for high-stakes containment decisions.

**Rationale:** Security operations involve irreversible actions—quarantining production hosts, blocking executive accounts, notifying regulators. An LLM hallucination at the wrong moment creates catastrophic risk. The platform is designed so that every critical path ends with a human approval gate.

**Implementation Evidence:**
- `pkg/agents/approval.go` — ApprovalGate struct enforces human sign-off before containment actions
- `internal/workflow/orchestrator.go:142` — Agent output passes through `requiresApproval()` before execution
- `pkg/agents/config.go` — `MaxAutonomyLevel` per agent type; response agents capped at `DRAFT_ONLY`

**Anti-Patterns to Avoid:**
- Autonomous containment without human review (even for "obvious" cases)
- Trusting LLM confidence scores above 0.95 as sufficient for automated action
- Building "auto-respond" pipelines that bypass the approval gate
- Treating AI output as authoritative without MITRE ATT&CK validation

---

## 2. Self-Hosted Sovereignty

**Definition:** All platform components—LLM inference, vector stores, SIEM engine, agent orchestrator—are self-hosted. No alert data, log data, or enrichment data leaves the customer's infrastructure.

**Rationale:** SOC/MDR customers handle regulated data (HIPAA, PCI-DSS, FedRAMP). Sending alert payloads to third-party APIs creates compliance violations and vendor lock-in. Sovereignty means the customer can audit, modify, replace, or destroy any component at any time.

**Implementation Evidence:**
- `deploy/base/kustomization.yaml` — All services deployed as Kubernetes manifests; no external API calls
- `pkg/llm/providers/local.go` — Local LLM inference via Ollama or vLLM
- `pkg/vector/qdrant.go` — Qdrant runs in-cluster; no cloud vector DB dependencies
- `pkg/rag/embedding_cache.go` — Embeddings stored in local Qdrant; never sent externally

**Anti-Patterns to Avoid:**
- Calling external LLM APIs (OpenAI, Anthropic) for alert processing
- Using cloud-managed services (SaaS vector DBs, managed SIEM) without customer awareness
- Shipping telemetry or logs to vendor endpoints
- Requiring internet connectivity for core functionality

---

## 3. Defense in Depth

**Definition:** Four-layer architecture with clear separation of concerns. Failure in one layer does not compromise others. Each layer validates inputs from the layer above.

**Rationale:** Security platforms are high-value targets. A compromised agent must not give attackers access to the response layer. A vulnerability in the RAG pipeline must not leak credentials. Layered security means compromise of one component requires independent exploitation of the next.

**Implementation Evidence:**
- `docs/architecture.md` — Four layers: Collection → Processing → Analysis → Response
- `deploy/network-policies/` — Default-deny NetworkPolicy between namespaces
- `pkg/middleware/layer_validation.go` — Each layer validates payloads before passing downstream
- `internal/auth/layer_mtls.go` — mTLS between layers; no plaintext inter-service communication

**Anti-Patterns to Avoid:**
- Monolithic services that span multiple layers
- Shared databases between layers without access controls
- Trusting upstream layer output without validation
- Running all components in a single container or pod

---

## 4. Auditability by Design

**Definition:** Every agent action, LLM call, human approval, and system decision is logged with HMAC-SHA256 signatures. Full reasoning traces are preserved. All AI outputs include explainability metadata.

**Rationale:** SOC operations require forensic-grade audit trails. When an incident is reviewed—internally or by regulators—the platform must answer: what happened, who decided, when, and why. Tamper-evident logs prevent post-hoc modification.

**Implementation Evidence:**
- `pkg/audit/hmac.go` — HMAC-SHA256 signing of all log entries
- `pkg/audit/immutability.go` — Write-once log storage with hash chain verification
- `internal/agents/reasoning_trace.go` — Every agent call captures input, output, confidence, and reasoning
- `pkg/llm/explainability.go` — LLM responses include chain-of-thought metadata

**Anti-Patterns to Avoid:**
- Logging without integrity verification (plain text logs)
- Discarding reasoning traces after agent output is produced
- Allowing log entries to be modified or deleted after creation
- Making audit logs inaccessible to customers

---

## 5. Security by Default

**Definition:** The platform deploys with secure defaults. Zero-configuration deployment results in: default-deny network policies, input validation on all endpoints, prompt injection guards active, least-privilege IAM roles, encrypted storage.

**Rationale:** The most common security failures come from misconfiguration. If secure behavior requires opt-in, most deployments will be insecure. Secure defaults mean the platform is hardened from the first `kubectl apply`.

**Implementation Evidence:**
- `deploy/base/` — All manifests ship with restrictive defaults
- `pkg/validation/alert_payload.go` — JSON Schema validation rejects malformed alerts
- `pkg/security/prompt_guard.go` — 11 regex patterns block prompt injection attempts
- `pkg/security/control_chars.go` — Control character sanitization on all inputs
- `deploy/rbac/` — ClusterRoles scoped to minimum required permissions

**Anti-Patterns to Avoid:**
- Shipping with `ClusterAdmin` bindings
- Disabling input validation "for performance"
- Requiring customers to manually enable security features
- Logging secrets or credentials in debug mode

---

## 6. GitOps Everything

**Definition:** Infrastructure as Code. Declarative configuration. Automated reconciliation. Every change to production goes through version control, review, and automated deployment.

**Rationale:** GitOps provides auditability, rollback, and reproducibility. Manual changes to production are invisible, unrecoverable, and unauditable. Declarative state means the system continuously converges toward the desired configuration.

**Implementation Evidence:**
- `deploy/` — Complete Kubernetes manifests in Git
- `Makefile` — ArgoCD sync targets; `make sync` applies declarative state
- `pkg/gitops/reconciler.go` — Reconciliation loop compares desired vs. actual state
- `.github/workflows/deploy.yml` — CI/CD pipeline triggers on merge to main

**Anti-Patterns to Avoid:**
- Manual `kubectl edit` or `kubectl patch` in production
- Snowflake configurations not tracked in Git
- `kubectl port-forward` as a permanent debugging solution
- Skipping reconciliation for "temporary" changes

---

## 7. Cost Awareness

**Definition:** Every LLM call is budgeted. Token usage per agent is tracked. Embedding costs are cached. Batch processing reduces per-alert cost. Cost monitoring dashboards are visible to operators.

**Rationale:** LLM costs scale linearly with alert volume. A platform processing 50K alerts/month without cost controls will generate unsustainable bills. Cost awareness is not optional—it is an architectural constraint that shapes agent design, model selection, and processing pipelines.

**Implementation Evidence:**
- `pkg/llm/token_budget.go` — Per-agent token budgets enforced at the provider level
- `pkg/rag/embedding_cache.go` — Cache hit rate >80% for repeated embeddings
- `pkg/batch/processor.go` — Batch similar alerts for single LLM calls
- `internal/dashboard/cost.go` — Grafana dashboard tracking daily spend per agent

**Anti-Patterns to Avoid:**
- Unbounded LLM calls without token limits
- Using GPT-4o for trivial triage that Groq handles for free
- Ignoring embedding costs (vector DB operations are not free)
- Not tracking per-customer cost for MDR billing

---

## 8. Human-in-the-Loop

**Definition:** All destructive actions require human approval. Configurable autonomy thresholds allow customers to define what the platform can do without approval. Escalation on timeout ensures no action is silently dropped.

**Rationale:** Automation without oversight creates liability. A customer's security team must retain control over their environment. Human-in-the-loop is not a failure of automation—it is a design feature that provides accountability and trust.

**Implementation Evidence:**
- `pkg/agents/approval.go` — ApprovalGate with configurable timeout and escalation
- `internal/workflow/orchestrator.go:189` — `escalateOnTimeout()` sends to next tier if no approval within SLA
- `pkg/agents/config.go` — `AutonomyLevel` enum: `FULL_AUTO`, `DRAFT_ONLY`, `READ_ONLY`, `DISABLED`
- `internal/escalation/manager.go` — Escalation chain: L1 → L2 → L3 → CISO

**Anti-Patterns to Avoid:**
- Defaulting to `FULL_AUTO` for containment actions
- Implementing "approval" as a rubber-stamp notification
- Allowing timeout expiry to default to "approved"
- Bypassing approval for "routine" incidents

---

## 9. Composable Services

**Definition:** Each service is independently deployable. Clear API contracts between services. Loose coupling through message queues and event streams. Services can be replaced without modifying consumers.

**Rationale:** Security operations evolve rapidly. New data sources, new LLM providers, new response actions must be integrable without rewriting the platform. Composability means customers can replace components with alternatives that fit their requirements.

**Implementation Evidence:**
- `pkg/api/contracts/` — OpenAPI specs for every service interface
- `internal/messaging/nats.go` — NATS JetStream for inter-service communication
- `deploy/services/` — Independent Deployment manifests per service
- `pkg/rag/provider.go` — Pluggable vector store interface; Qdrant, Milvus, Weaviate supported

**Anti-Patterns to Avoid:**
- Tight coupling through shared databases
- Hardcoded service discovery (IP addresses, fixed ports)
- Monolithic APIs that expose internal service boundaries
- Requiring all services to upgrade simultaneously

---

## 10. Observable by Default

**Definition:** Structured logging (JSON). Distributed tracing (OpenTelemetry). Metrics on every component (Prometheus). Pre-built dashboards (Grafana). Alerting on platform health.

**Rationale:** A security platform that is not observable cannot be trusted. Operators must understand what the platform is doing, why agents made decisions, where bottlenecks exist, and what is failing. Observability is not a feature—it is a prerequisite for operational trust.

**Implementation Evidence:**
- `pkg/observability/logger.go` — Structured JSON logging with correlation IDs
- `pkg/observability/tracer.go` — OpenTelemetry integration with trace propagation
- `pkg/observability/metrics.go` — Prometheus metrics for agent latency, LLM cost, queue depth
- `deploy/grafana/dashboards/` — Pre-built dashboards for SOC operations, cost, system health

**Anti-Patterns to Avoid:**
- Unstructured log messages (`log.Printf("something happened")`)
- Missing trace context propagation between services
- Metrics without labels (making per-agent breakdown impossible)
- Dashboards that require manual creation after deployment
