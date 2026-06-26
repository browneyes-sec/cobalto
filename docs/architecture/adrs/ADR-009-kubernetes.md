# ADR-009: Kubernetes (EKS) for Container Orchestration

| Field       | Value          |
|-------------|----------------|
| **Status**  | Accepted       |
| **Date**    | 2025-01-15     |
| **Authors** | Platform Engineering |

## Context

The SOC platform consists of 15+ microservices that require:
- Automated deployment and scaling
- Service discovery and load balancing
- Rolling updates with zero downtime
- Resource isolation and limits
- Consistent environment across dev/staging/prod

Manual orchestration or single-container deployments cannot meet these requirements at scale.

## Decision

Deploy **AWS EKS** (Elastic Kubernetes Service) as the container orchestration platform, with **Kustomize** for configuration management and **Flux CD** for GitOps-based continuous delivery.

## Alternatives Considered

| Alternative                   | Pros                                      | Cons                                              | Verdict     |
|-------------------------------|-------------------------------------------|----------------------------------------------------|-------------|
| **AWS ECS/Fargate**           | Simpler, AWS-managed                      | AWS-specific, limited portability, no Helm         | Rejected    |
| **HashiCorp Nomad**           | Simpler than K8s, multi-runtime           | Smaller ecosystem, less community tooling          | Rejected    |
| **Docker Swarm**              | Simple setup, Docker-native               | Limited scaling, minimal ecosystem, declining use  | Rejected    |
| **K3s**                       | Lightweight, easy setup                   | Not production-grade for large workloads           | Rejected    |

## Consequences

### Positive
- Industry-standard container orchestration with massive ecosystem
- Horizontal Pod Autoscaler (HPA) for workload-based scaling
- Rolling updates and canary deployments with zero downtime
- Rich service mesh integration (Istio/Linkerd)
- GitOps workflow with Flux CD ensures auditability and reproducibility
- Portability across cloud providers and on-premises
- Kustomize overlays for environment-specific configuration without templating

### Negative
- Significant operational complexity (cluster upgrades, node management)
- Steep learning curve for Kubernetes concepts and debugging
- Resource overhead for control plane components
- Network policy and RBAC configuration requires careful planning
- Stateful workloads (databases, Qdrant) require persistent volume management

### Risks and Mitigations

| Risk                                    | Likelihood | Impact | Mitigation                                    |
|-----------------------------------------|------------|--------|-----------------------------------------------|
| Cluster upgrade breaks services         | Medium     | High   | Staged upgrades, PDBs, canary node groups     |
| Node capacity exhaustion                | Medium     | High   | Cluster autoscaler, spot instances for batch   |
| Misconfigured network policies          | Medium     | Medium | Policy-as-code, staging validation             |
| Persistent volume data loss             | Low        | High   | EBS volumes, backup with Velero               |
| Flux sync failure blocks deployments    | Low        | High   | Alert on sync status, manual override procedure|

## Cluster Topology

| Node Group        | Instance Type    | Min | Max | Purpose                    |
|-------------------|------------------|-----|-----|----------------------------|
| system            | m6i.large        | 3   | 3   | Control plane add-ons      |
| application       | m6i.xlarge       | 4   | 16  | Core SOC services          |
| data              | r6i.2xlarge      | 3   | 8   | Elasticsearch, Qdrant      |
| batch             | c6i.2xlarge      | 0   | 10  | Agent processing jobs      |

## GitOps Workflow

```
Developer ──▶ Git Push ──▶ Flux detects change ──▶ Kustomize build ──▶ Apply to cluster
                                │
                                ├──▶ health checks
                                ├──▶ rollback on failure
                                └──▶ notification to Slack
```

## Namespace Layout

| Namespace          | Services                                    |
|--------------------|---------------------------------------------|
| `cobalto-system`   | Vault, Prometheus, Grafana, Flux            |
| `cobalto-core`     | LangGraph agent, n8n, orchestrator          |
| `cobalto-data`     | PostgreSQL, Elasticsearch, Qdrant, Redis    |
| `cobalto-intel`    | OpenCTI, TheHive, Cortex, MISP              |
| `cobalto-monitor`  | Alertmanager, Loki, Tempo                   |
