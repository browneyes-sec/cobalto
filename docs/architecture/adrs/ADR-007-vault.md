# ADR-007: HashiCorp Vault for Secrets Management

| Field       | Value          |
|-------------|----------------|
| **Status**  | Accepted       |
| **Date**    | 2025-01-15     |
| **Authors** | Platform Engineering |

## Context

The SOC platform requires secure management of secrets across all services, including:
- API keys for third-party integrations (VirusTotal, Shodan, MISP)
- Database credentials (PostgreSQL, Elasticsearch, Qdrant)
- TLS certificates for mTLS between microservices
- OAuth tokens for Slack, TheHive, and analyst tools

Secrets are currently hardcoded in environment variables and configuration files, creating security risks and operational overhead for credential rotation.

## Decision

Deploy **HashiCorp Vault** as the centralized secrets management solution for all environments.

## Alternatives Considered

| Alternative                   | Pros                                      | Cons                                              | Verdict     |
|-------------------------------|-------------------------------------------|----------------------------------------------------|-------------|
| **AWS Secrets Manager**       | Managed, auto-rotation for RDS            | Vendor lock-in, per-secret pricing, limited scope  | Rejected    |
| **Kubernetes Secrets**        | Native, simple API                        | Base64 only, not encrypted at rest by default      | Rejected    |
| **SOPS + KMS**                | Git-friendly, encrypted files             | No dynamic secrets, no PKI, no audit logging       | Rejected    |
| **Infisical**                 | Open-source, modern UI                    | Less mature, limited enterprise features            | Rejected    |

## Consequences

### Positive
- Dynamic database credentials with automatic 24-hour rotation
- KV store v2 for API keys with versioning and soft delete
- PKI engine for automated mTLS certificate issuance and renewal
- Comprehensive audit logging of all secret access
- AppRole and Kubernetes auth methods for service identity
- Encryption as a service via Transit engine

### Negative
- Operational complexity: Vault cluster requires 3-5 nodes for HA
- Sealed/unsealed state management requires procedures
- Additional infrastructure to monitor and maintain
- Learning curve for team (Vault policies, engines, auth methods)
- Backup and disaster recovery procedures must be established

### Risks and Mitigations

| Risk                                    | Likelihood | Impact | Mitigation                                    |
|-----------------------------------------|------------|--------|-----------------------------------------------|
| Vault unavailability blocks services    | Low        | High   | HA deployment, local cached credentials fallback |
| Unsealing failures during incident      | Medium     | High   | Auto-unseal with KMS, documented procedures   |
| Secrets rotation causes service restart | Medium     | Medium | Graceful rotation with connection pooling     |
| Policy misconfiguration leaks secrets   | Low        | High   | Policy-as-code, PR reviews, least privilege    |

## Secret Engines

| Engine         | Path              | Purpose                                    |
|----------------|-------------------|--------------------------------------------|
| KV v2          | `secret/cobalto/` | API keys, config values                    |
| Database       | `database/`       | Dynamic PostgreSQL/ES credentials          |
| PKI            | `pca/`            | Internal mTLS certificates                 |
| Transit        | `transit/`        | Application-level encryption               |

## Auth Methods

| Method     | Use Case                              |
|------------|----------------------------------------|
| Kubernetes | Pod identity via service account token |
| AppRole    | CI/CD pipelines, external systems      |
| AWS IAM    | EC2/Lambda workloads                   |
| Userpass   | Human operators (emergency access)     |
