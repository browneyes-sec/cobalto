# ADR-005: Qdrant as Vector Store for MITRE ATT&CK RAG

## Status

Accepted

## Date

2026-06-25

## Context

Cobalto SOC/MDR uses a LangGraph agent that maps Wazuh alerts to MITRE ATT&CK techniques. This requires semantic search over the full ATT&CK knowledge base (techniques, sub-techniques, procedures) to provide context for threat analysis.

Requirements:

- Store vector embeddings of MITRE ATT&CK documents
- Perform real-time similarity search (<100ms latency)
- Support filtering by technique ID, tactic, platform
- Deploy as a self-hosted service within the Kubernetes cluster
- Integrate with the existing Python tooling in LangGraph agent

Candidate vector stores:

1. **Qdrant** - Open-source vector database
2. **Pinecone** - Managed vector database (not evaluated due to vendor lock-in concerns)
3. **Milvus** - Open-source vector database
4. **Weaviate** - Open-source vector database

## Decision

We will use **Qdrant** as the vector store for MITRE ATT&CK RAG.

## Consequences

### Positive

- **Open source**: Apache 2.0 license; no vendor lock-in
- **Performance**: Written in Rust; sub-10ms query latency on embeddings up to 1536 dimensions
- **Filtering**: Native payload filtering for technique ID, tactic, platform queries
- **Easy deployment**: Single binary with minimal dependencies; straightforward Kubernetes deployment
- **Python client**: Official `qdrant-client` library with sync and async support
- **Scalability**: Supports horizontal scaling with sharding and replication
- **RAG-native**: Designed for RAG workloads with payload-based filtering and collection management

### Negative

- **Operational overhead**: Self-hosted solution requires monitoring, backups, and upgrades
- **Ecosystem**: Smaller ecosystem compared to Pinecone; fewer managed service options
- **Documentation**: Community documentation is improving but less mature than established databases

### Risks

- Single-node deployment may become a bottleneck at scale (mitigated by clustering support)
- Vector dimension changes require re-indexing (mitigated by versioning collections)
- Open-source dependency requires monitoring for security patches (mitigated by active community)
