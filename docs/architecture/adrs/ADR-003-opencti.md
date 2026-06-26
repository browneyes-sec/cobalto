# ADR-003: OpenCTI over MISP-only

## Status

Accepted

## Date

2026-06-25

## Context

Cobalto SOC/MDR requires a threat intelligence platform to manage IOCs, threat actor profiles, campaigns, and enable automated enrichment of security alerts. Requirements include:

- IOC management with reputation scoring and lifecycle tracking
- Threat actor and campaign profiling with relationship mapping
- API-first design for integration with LangGraph agent and n8n workflows
- Support for STIX/TAXII standards for threat intel sharing
- Ability to consume and produce threat intelligence feeds
- Scalable storage for millions of IOCs
- Visual exploration of threat intelligence relationships

Candidate platforms:

1. **OpenCTI** - Open-source threat intelligence platform
2. **MISP-only** - Malware Information Sharing Platform as sole TIP
3. **MISP + custom extensions** - MISP with custom enrichment layers

## Decision

We will use **OpenCTI** as the primary threat intelligence platform, with MISP as a secondary feed source for specific malware-focused intelligence sharing communities.

## Consequences

### Positive

- **Rich data model**: OpenCTI supports STIX 2.1 natively with support for complex entity relationships (threat actors → campaigns → indicators → observables)
- **Visualization**: Built-in knowledge graphs enable analysts to explore threat relationships visually
- **API-first**: GraphQL API provides flexible querying for LangGraph agent integration
- **Feed management**: Native support for consuming STIX/TAXII feeds, RSS, and MISP feeds
- **Reporting**: Automated report generation and customizable dashboards
- **Collaboration**: Multi-user support with role-based access and workspace isolation
- **Active development**: Backward with large enterprise deployments and commercial support available

### Negative

- **Resource requirements**: OpenCTI requires significant infrastructure (Elasticsearch, Redis, MinIO) compared to MISP
- **Complexity**: More complex deployment and configuration than MISP
- **Learning curve**: Rich data model requires training for analysts to use effectively
- **MISP integration**: Bi-directional sync with MISP communities adds operational overhead

### Risks

- Infrastructure complexity increases operational burden (mitigated by Kubernetes deployment and monitoring)
- Data model complexity may slow analyst adoption (mitigated by training and curated views)
- Potential data staleness if feeds are not regularly updated (mitigated by automated feed scheduling)
