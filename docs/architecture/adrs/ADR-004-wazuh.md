# ADR-004: Wazuh over Elastic SIEM

## Status

Accepted

## Date

2026-06-25

## Context

Cobalto SOC/MDR requires a SIEM/XDR platform for security event collection, correlation, and alert generation. The platform must:

- Collect and normalize logs from diverse sources (endpoints, cloud, network)
- Provide correlation rules for threat detection
- Support agent-based endpoint monitoring (FIM, rootkit detection, vulnerability scanning)
- Enable automated response actions (host isolation, command execution)
- Scale to thousands of endpoints across multiple clients
- Maintain SOC 2 Type II compliance for data handling
- Support multi-tenant deployment for MDR service delivery

Candidate platforms:

1. **Wazuh** - Open-source SIEM/XDR platform
2. **Elastic SIEM** - Elastic Stack security solution
3. **Splunk Enterprise Security** - Commercial SIEM (not evaluated due to cost)

## Decision

We will use **Wazuh** as the primary SIEM/XDR platform.

## Consequences

### Positive

- **Open source**: No licensing costs; full code access for customization
- **Integrated XDR**: Single platform combines SIEM, FIM, vulnerability detection, and response
- **Agent capabilities**: Native endpoint agents provide FIM, rootkit detection, CIS benchmarks, and active response
- **Scalability**: Proven at 100,000+ endpoints with cluster architecture
- **Multi-tenancy**: Built-in RBAC and tenant isolation for MDR service delivery
- **Compliance**: Pre-built compliance maps (PCI DSS, HIPAA, GDPR, CIS)
- **Integration**: REST API for LangGraph/n8n integration; native Elastic Stack output
- **Cost effective**: Enterprise features without enterprise licensing

### Negative

- **Elastic dependency**: While open-source, Wazuh relies on Elastic Stack for storage and visualization
- **Rule management**: Custom detection rules require YAML configuration rather than visual rule builder
- **Documentation**: Community documentation can be inconsistent; enterprise support recommended
- **UI limitations**: Dashboard and visualization capabilities lag behind Elastic SIEM and Splunk

### Risks

- Elastic Stack licensing changes could impact deployment (mitigated by OpenSearch compatibility)
- Community-driven development may have slower response to zero-days (mitigated by Wazuh Inc. backing)
- Scaling beyond 100k endpoints may require architecture optimization (mitigated by proven cluster design)
