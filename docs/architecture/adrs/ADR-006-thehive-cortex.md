# ADR-006: TheHive + Cortex for Case Management and Enrichment

| Field       | Value          |
|-------------|----------------|
| **Status**  | Accepted       |
| **Date**    | 2025-01-15     |
| **Authors** | SOC Engineering |

## Context

The SOC platform requires a centralized case management system to track incidents, manage analyst workflows, and orchestrate observable enrichment across multiple threat intelligence sources. Analysts need a unified workspace to triage alerts, correlate observables, and collaborate on investigations.

Current pain points:
- No structured case lifecycle management
- Manual enrichment workflows consuming analyst time
- No correlation between observables across cases
- Lack of audit trail for investigation actions

## Decision

Adopt **TheHive 5.x** as the primary case management platform and **Cortex** for automated observable enrichment and analysis.

## Alternatives Considered

| Alternative                   | Pros                                      | Cons                                           | Verdict     |
|-------------------------------|-------------------------------------------|------------------------------------------------|-------------|
| **TheHive 4.x**               | Stable, large community                   | Legacy architecture, limited API, EOL soon     | Rejected    |
| **Custom case tracker**       | Full control, tailored workflows          | High dev cost, no ecosystem, maintenance burden | Rejected    |
| **Splunk SOAR**               | Enterprise support, playbook engine       | Commercial licensing, vendor lock-in, costly    | Rejected    |
| **Shuffle SOAR**              | Open-source, modular                      | Less mature case management, smaller community | Rejected    |

## Consequences

### Positive
- Best-in-class open-source case management with native Cortex integration
- Observable correlation across cases with automatic tagging
- Analyst workspace with customizable dashboards and metrics
- Rich API for programmatic case and alert management
- Built-in analyzer/responder ecosystem (30+ integrations)
- Active community with regular updates

### Negative
- AGPL license requires source disclosure for modified deployments
- Java/JVM runtime requirement increases container image size (~300MB baseline)
- Significant memory footprint (recommended: 4GB+ heap for TheHive, 2GB+ for Cortex)
- Migration path to TheHive 6.x (expected 2025) will require data migration planning

### Risks and Mitigations

| Risk                                    | Likelihood | Impact | Mitigation                                    |
|-----------------------------------------|------------|--------|-----------------------------------------------|
| JVM memory pressure under load          | Medium     | High   | Horizontal scaling, resource limits, monitoring |
| TheHive 6 migration complexity          | High       | Medium | Maintain clean data model, test migration early |
| AGPL compliance requirements            | Low        | Medium | Legal review, no modifications to core code    |
| Cortex connector maintenance            | Medium     | Low    | Pin versions, test updates in staging          |

## Integration Points

```
n8n Webhook ──POST /api/case──▶ TheHive ──▶ Cortex (enrichment)
                                    │              │
                                    ▼              ▼
                              Elasticsearch    OpenCTI / MISP
                              (case storage)   (threat intel)
```
