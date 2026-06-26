# ADR-008: Grafana + Prometheus for Observability

| Field       | Value          |
|-------------|----------------|
| **Status**  | Accepted       |
| **Date**    | 2025-01-15     |
| **Authors** | Platform Engineering |

## Context

The SOC platform requires comprehensive observability for:
- **SOC KPIs**: Mean time to detect (MTTD), mean time to respond (MTTR), cases per analyst
- **Agent performance**: LangGraph agent latency, tool call success rates, token consumption
- **Infrastructure metrics**: CPU, memory, disk, network across all services
- **Cost tracking**: Per-service resource consumption, API call costs, storage usage

Without centralized observability, the team cannot measure effectiveness, detect performance degradation, or optimize resource allocation.

## Decision

Deploy **Grafana** for dashboards and visualization, **Prometheus** for metrics collection and storage, and **Alertmanager** for alert routing.

## Alternatives Considered

| Alternative                   | Pros                                      | Cons                                           | Verdict     |
|-------------------------------|-------------------------------------------|------------------------------------------------|-------------|
| **Datadog**                   | Full-stack, AI-powered                    | Commercial, per-host pricing ($23+/host/mo)    | Rejected    |
| **CloudWatch**                | AWS-native, low setup                     | AWS-specific, limited custom dashboards        | Rejected    |
| **Elasticsearch + Kibana**    | Already in stack for logs                 | Not optimized for metrics, higher resource use | Rejected    |
| **Custom dashboards**         | Full control                              | High maintenance, no ecosystem                  | Rejected    |

## Consequences

### Positive
- Self-hosted with no per-host or per-metric pricing
- 100+ Prometheus exporters and integrations
- Rich community dashboard ecosystem (Grafana.com)
- PromQL for powerful metric querying
- Alertmanager with routing, silencing, and inhibition
- Native Kubernetes service discovery
- Long-term storage via Thanos or Prometheus ruler

### Negative
- Self-managed infrastructure requires maintenance
- Prometheus retention limited without remote storage (~15-30 days default)
- Alertmanager configuration complexity for multi-channel routing
- Grafana dashboard management requires version control discipline

### Risks and Mitigations

| Risk                                    | Likelihood | Impact | Mitigation                                    |
|-----------------------------------------|------------|--------|-----------------------------------------------|
| Prometheus storage grows unbounded      | Medium     | Medium | Retention policies, Thanos for long-term      |
| Alert fatigue from noisy thresholds     | High       | Medium | Alert tuning, severity tiers, cooldown periods|
| Dashboard drift across environments     | Medium     | Low    | Dashboard-as-code with provisioning           |
| Metric cardinality explosion            | Low        | High   | Relabeling, recording rules, limits           |

## Stack Components

| Component       | Version | Purpose                    |
|-----------------|---------|----------------------------|
| Prometheus      | 2.50+   | Metrics collection/storage |
| Grafana         | 10.4+   | Dashboards and visualization |
| Alertmanager    | 0.27+   | Alert routing and notification |
| Loki            | 2.9+    | Log aggregation (optional) |
| Tempo           | 2.4+    | Distributed tracing (optional) |

## Key Dashboards

| Dashboard              | Audience       | Refresh Rate |
|------------------------|----------------|-------------- |
| SOC Operations         | SOC Managers   | 30s           |
| Agent Performance      | Engineering    | 15s           |
| Infrastructure Health  | SRE            | 60s           |
| Cost Tracking          | Finance/Ops    | 5m            |
