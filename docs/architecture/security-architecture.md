# Security Architecture

## Platform Self-Protection

The Cobalto platform is designed to defend itself against the same class of attacks it detects in customer environments. The platform assumes an adversarial model where attackers may attempt to manipulate agent inputs, exfiltrate secrets, tamper with alert data, or disrupt SOC operations.

### Threat Model

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Alert injection | Attacker crafts alerts to manipulate agent behavior | Input validation, prompt injection guard |
| Secret exfiltration | Agent or workflow extracts credentials | Vault dynamic secrets, short-lived tokens |
| Data tampering | Modification of alert/case data in transit or at rest | HMAC receipts, encrypted storage, audit logs |
| Denial of service | Flooding the agent service with requests | Rate limiting, circuit breakers, K8s resource limits |
| Privilege escalation | Lateral movement within the platform | mTLS, network policies, least-privilege IAM |
| Model manipulation | Prompt injection to override agent instructions | PromptInjectionGuard, system prompt isolation |

## Agent Security Controls

The LangGraph Agent Service enforces 8 mandatory security controls on every execution.

| # | Control | Implementation | Evidence |
|---|---------|---------------|----------|
| 1 | Input Validation | Pydantic models with strict mode, reject unknown fields | Validation error logs in Elasticsearch |
| 2 | Prompt Injection Prevention | Two-layer guard: regex patterns + ML classifier (DistilBERT) | Blocked request logs with confidence scores |
| 3 | Tool Permission Scoping | Each agent node has a whitelist of allowed tool calls | Tool permission map in config, violation alerts |
| 4 | Execution Receipt HMAC | Every tool call produces an HMAC-SHA256 receipt | Receipts stored in PostgreSQL, verifiable |
| 5 | Model Context Protocol (MCP) | Agent system prompts isolated, no cross-agent context leakage | MCP audit logs, prompt hash verification |
| 6 | Rate Limiting | Token bucket per-IP (100 req/min), per-agent-node (10 calls/min) | Rate limit metrics in Prometheus, block logs |
| 7 | Model Context Protocol (MCP) | Structured tool call schemas, no free-form execution | Tool call validation logs |
| 8 | Audit Trail | Every action logged to append-only Elasticsearch index | Immutable audit index with WORM policy |

### Control Details

#### 1. Input Validation

All inputs to the agent service are validated against strict Pydantic models. Unknown fields are rejected. Alert payloads are schema-validated before graph execution begins.

```python
class AlertInput(BaseModel):
    model_config = ConfigDict(strict=True)

    alert_id: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(pattern=r"^\\d{4,6}$")
    rule_level: int = Field(ge=1, le=15)
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    source_port: int = Field(ge=1, le=65535)
    destination_port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp", "icmp"]
    full_log: str = Field(max_length=65536)
```

#### 2. Prompt Injection Prevention

Two-layer defense against prompt injection attacks:

1. **Regex layer:** Scans for 40+ known injection patterns including:
   - Instruction override attempts (`ignore previous instructions`, `disregard all rules`)
   - System prompt extraction (`what is your system prompt`, `print your instructions`)
   - Delimiter injection (`<|im_start|>`, `</s>`, `[INST]`)
   - Role manipulation (`you are now`, `act as`, `pretend to be`)

2. **ML layer:** Fine-tuned DistilBERT classifier (74k training samples, 97.3% accuracy) that detects semantically adversarial inputs even when they evade regex patterns.

**Response:** Blocked requests return HTTP 422 with sanitized error. Full request context logged to audit trail.

#### 3. Tool Permission Scoping

Each agent node has a strict whitelist of allowed tool calls:

| Node | Allowed Tools | Denied Tools |
|------|--------------|--------------|
| triage | `mitre_attack_search` | `enrich_ioc`, `opencti_query`, `wazuh_active_response` |
| analysis | `mitre_attack_search`, `cmdb_lookup` | `enrich_ioc`, `opencti_query` |
| threat_intel | `opencti_query`, `enrich_ioc` | `mitre_attack_search`, `wazuh_active_response` |
| response | `wazuh_active_response`, `thehive_create_case` | `mitre_attack_search`, `opencti_query` |
| human_gate | None (no tool calls) | All tools |
| documentation | `thehive_update_case` | All other tools |
| escalate | `thehive_create_case`, `pagerduty_trigger` | All other tools |

**Violation handling:** Unauthorized tool calls are blocked before execution and logged as security events.

#### 4. Execution Receipt HMAC

Every tool call produces a signed receipt that can be verified independently:

```python
import hmac, hashlib, json

def create_execution_receipt(
    node: str,
    tool: str,
    args: dict,
    result: dict,
    secret: str
) -> dict:
    payload = json.dumps({
        "node": node,
        "tool": tool,
        "args": args,
        "result_hash": hashlib.sha256(json.dumps(result).encode()).hexdigest(),
        "timestamp": datetime.utcnow().isoformat()
    }, sort_keys=True)
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}
```

Receipts are stored in PostgreSQL and can be verified by auditors using the HMAC secret.

#### 5. Model Context Protocol (MCP)

Agent system prompts are isolated per node. No agent can access another agent's system prompt or conversation history. The MCP enforces:

- System prompt hash verification on each execution
- No cross-agent context leakage
- Structured tool call schemas (no free-form execution)
- Tool call arguments validated against parameter schemas before execution

#### 6. Rate Limiting

Token bucket algorithm with two dimensions:

| Scope | Limit | Bucket Size | Refill Rate |
|-------|-------|-------------|-------------|
| Per IP | 100 requests/min | 100 tokens | 1.67 tokens/sec |
| Per agent node | 10 tool calls/min | 10 tokens | 0.17 tokens/sec |
| Per tool | 50 calls/min | 50 tokens | 0.83 tokens/sec |

**Burst handling:** Short bursts (up to 2× limit) are allowed with a warning header. Sustained over-limit triggers HTTP 429 with `Retry-After` header.

#### 7. Audit Trail

Every action in the system is logged to an append-only Elasticsearch index with WORM (Write Once Read Many) policy:

```json
{
  "timestamp": "2026-06-25T10:30:00Z",
  "event_type": "tool_call",
  "node": "threat_intel",
  "tool": "opencti_query",
  "run_id": "uuid",
  "request_hash": "sha256:...",
  "response_hash": "sha256:...",
  "hmac_receipt": "sha256:...",
  "latency_ms": 2340,
  "success": true,
  "user_context": "system"
}
```

**Retention:** Audit logs retained for 7 years in S3-IA, with 1 year in hot Elasticsearch storage.

## Secrets Management

### HashiCorp Vault

All secrets are managed through HashiCorp Vault with the following engines:

| Engine | Purpose | Configuration |
|--------|---------|---------------|
| KV v2 | Static secrets (API keys, passwords) | `cobalt/` mount, versioned |
| Dynamic DB | Database credentials (PostgreSQL) | 1-hour TTL, auto-rotation |
| PKI | Internal TLS certificates | Root CA + intermediate, 24h certs |
| Transit | Encryption as a service | AES-256-GCM, automatic key rotation |
| Audit | Vault access logging | File + syslog backend |

### Secret Rotation

| Secret Type | Rotation Period | Method |
|-------------|----------------|--------|
| Database credentials | 1 hour | Vault dynamic secrets |
| API keys (Cortex, OpenCTI) | 24 hours | Vault KV with webhook trigger |
| TLS certificates | 24 hours | Vault PKI, automatic via sidecar |
| JWT signing keys | 12 hours | Vault Transit, kid rotation |

### Audit Log

Vault audit logging captures every secret access:

```json
{
  "type": "request",
  "time": "2026-06-25T10:30:00Z",
  "auth": {
    "client_token": "hmac-sha256:...",
    "accessor": "hmac-sha256:...",
    "policies": ["cobalt-agent"]
  },
  "request": {
    "operation": "read",
    "path": "cobalt/data/api-keys/virustotal",
    "remote_address": "10.0.1.50"
  },
  "error": ""
}
```

## Network Security

### VPC Architecture

```
┌─────────────────────────────────────────────────┐
│                    VPC (10.0.0.0/16)              │
├──────────────────────┬──────────────────────────┤
│   Public Subnet      │   Private Subnet          │
│   10.0.0.0/20        │   10.0.16.0/20            │
├──────────────────────┼──────────────────────────┤
│   NAT Gateway        │   LangGraph Agent         │
│   ALB Ingress        │   n8n Workflows           │
│   Bastion Host       │   TheHive                 │
│                      │   Cortex                  │
│                      │   OpenCTI                 │
│                      │   Elasticsearch           │
│                      │   PostgreSQL              │
│                      │   Redis                   │
│                      │   Qdrant                  │
│                      │   Vault                   │
├──────────────────────┴──────────────────────────┤
│   Data Subnet (10.0.32.0/20)                     │
│   S3 VPC Endpoint                                │
│   Database replicas                              │
│   Backup storage                                 │
└─────────────────────────────────────────────────┘
```

### mTLS

All service-to-service communication uses mutual TLS via Istio:

- **Certificate issuer:** Istio Citadel (istiod)
- **Certificate lifetime:** 24 hours (auto-rotation)
- **Identity:** SPIFFE identity (`spiffe://cluster.local/ns/cobalt/sa/<service-account>`)
- **Mode:** STRICT — all traffic must present valid client certificates

### Web Application Firewall (WAF)

The Cobalt Console ingress is protected by AWS WAF:

| Rule | Type | Action |
|------|------|--------|
| SQL injection | Managed rule (AWS) | Block |
| XSS | Managed rule (AWS) | Block |
| Rate limiting | Custom | Throttle at 1000 req/min per IP |
| Geo blocking | Custom | Block traffic from non-approved regions |
| Known bad IPs | Managed rule (AWS) | Block |
| Custom SOC rules | Custom | Block known attack patterns |

### Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: langgraph-agent
  namespace: cobalt
spec:
  podSelector:
    matchLabels:
      app: langgraph-agent
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: n8n
      ports:
        - port: 8000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: qdrant
      ports:
        - port: 6333
    - to:
        - podSelector:
            matchLabels:
              app: elasticsearch
      ports:
        - port: 9200
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - port: 5432
    - to:
        - podSelector:
            matchLabels:
              app: vault
      ports:
        - port: 8200
```

### Security Groups

| Service | Inbound | Outbound |
|---------|---------|----------|
| LangGraph Agent | 8000 from n8n | 6333 (Qdrant), 9200 (ES), 5432 (PG), 8200 (Vault) |
| n8n | 5678 from ALB, 5678 from Wazuh | 8000 (LangGraph), 9000 (TheHive), 55000 (Wazuh) |
| TheHive | 9000 from n8n, 9000 from Console | 5432 (PG), 9200 (ES) |
| PostgreSQL | 5432 from LangGraph, TheHive, n8n | None |
| Qdrant | 6333 from LangGraph | None |
| Elasticsearch | 9200 from all services | 443 (S3 backup) |

## Container Security

### Image Scanning

| Layer | Tool | Frequency | Threshold |
|-------|------|-----------|-----------|
| Base image | Trivy | Build time | Critical: 0, High: 0 |
| Dependencies | Trivy | Build time | Critical: 0, High: ≤ 5 |
| Runtime | Falco | Continuous | Alert on syscall anomalies |
| Registry | Harbor | On push | Block Critical/High CVEs |

### Runtime Security

| Control | Implementation |
|---------|---------------|
| Non-root user | All containers run as UID 1000 (non-root) |
| Read-only filesystem | `readOnlyRootFilesystem: true` in K8s security context |
| Resource limits | CPU and memory limits enforced on every container |
| No privilege escalation | `allowPrivilegeEscalation: false` |
| Drop all capabilities | `capabilities: { drop: ["ALL"] }` |
| Seccomp profile | RuntimeDefault seccomp profile |
| AppArmor | Custom AppArmor profile for agent service |

### Resource Limits

| Container | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|--------------|
| langgraph-agent | 500m | 2000m | 512Mi | 2Gi |
| n8n | 250m | 1000m | 256Mi | 1Gi |
| thehive | 1000m | 4000m | 2Gi | 8Gi |
| elasticsearch | 2000m | 8000m | 4Gi | 16Gi |
| postgres | 1000m | 4000m | 2Gi | 8Gi |
| qdrant | 1000m | 4000m | 2Gi | 8Gi |

## Data Security

### Encryption at Rest

| Store | Method | Key Management |
|-------|--------|---------------|
| PostgreSQL | AES-256 ( Transparent Data Encryption ) | AWS KMS, auto-rotation |
| Elasticsearch | AES-256 ( index-level encryption ) | AWS KMS, per-index keys |
| Qdrant | AES-256 ( collection-level encryption ) | AWS KMS |
| S3 | SSE-KMS ( server-side encryption ) | AWS KMS, bucket key |
| Redis | AES-256 ( in-transit encryption only ) | N/A (ephemeral data) |

### Encryption in Transit

| Connection | Protocol | Certificate |
|------------|----------|-------------|
| Client → ALB | TLS 1.3 | AWS Certificate Manager |
| ALB → Services | mTLS (Istio) | Istio Citadel |
| Services → Databases | TLS 1.3 | Vault PKI |
| Services → External APIs | TLS 1.3 | System CA bundle |
| Vault | TLS 1.3 | Vault PKI |

### PII Masking

Sensitive data is masked before logging or storage:

| Data Type | Masking Rule | Example |
|-----------|-------------|---------|
| IP addresses | Hash (SHA-256) for non-IOC fields | `203.0.113.42` → `sha256:8a3f...` |
| Usernames | Mask middle characters | `john.doe` → `j***.d**` |
| Email addresses | Full mask | `john@example.com` → `***@***.com` |
| API keys | Mask all but last 4 | `sk-1234567890abcdef` → `sk-****cdef` |
| Passwords | Never logged | `[REDACTED]` |
| Credit card numbers | Mask all but last 4 | `4111111111111234` → `****1234` |

### Data Retention Policies

| Data Type | Hot Storage | Warm Storage | Cold Storage | Total |
|-----------|-------------|--------------|--------------|-------|
| Raw logs (Wazuh) | 90 days (Elasticsearch) | 1 year (S3-Standard) | 7 years (S3-IA) | 7 years |
| Alert data | Permanent (Elasticsearch) | — | — | Permanent |
| Incident cases | 2 years (PostgreSQL) | 5 years (S3-Standard) | 10 years (S3-IA) | 10 years |
| Agent audit logs | 1 year (Elasticsearch) | 7 years (S3-IA) | — | 7 years |
| Vault audit logs | 90 days (file) | 7 years (S3-IA) | — | 7 years |
| Vector embeddings | 1 year (Qdrant) | — | — | 1 year |
| Session data | 24 hours (Redis) | — | — | 24 hours |
| Reports (PDF/HTML) | 1 year (S3-Standard) | 7 years (S3-IA) | — | 7 years |

## Compliance Evidence

The platform produces the following evidence artifacts for auditors:

| Control | Evidence | Storage | Retention |
|---------|----------|---------|-----------|
| Access control | IAM policies, role bindings, audit logs | Elasticsearch, Vault audit | 7 years |
| Encryption at rest | KMS key policies, encryption configs | AWS CloudTrail | 7 years |
| Encryption in transit | TLS certificates, mTLS configs | Vault PKI, Istio configs | 7 years |
| Network segmentation | Network policies, security groups, VPC flow logs | K8s manifests, CloudWatch | 7 years |
| Vulnerability management | Trivy scan reports, Harbor CVE logs | S3 | 3 years |
| Incident response | Incident reports, SLA metrics, escalation logs | TheHive, PostgreSQL, S3 | 10 years |
| Audit trail | Append-only agent audit logs | Elasticsearch, S3-IA | 7 years |
| Secrets management | Vault audit logs, rotation records | Vault audit, S3 | 7 years |
| Data retention | Retention policy configs, deletion certificates | S3, K8s CronJob logs | Permanent |
| Container security | Image scan results, runtime profiles | Harbor, Falco, S3 | 3 years |
