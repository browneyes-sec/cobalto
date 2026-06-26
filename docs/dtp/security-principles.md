# Security Architecture Principles

> Security controls implemented across the Cobalto Agentic SOC/MDR platform, mapped to their implementation.

---

## 1. Security-by-Default

**What Happens with Zero Configuration:**

When deployed with `kubectl apply -k deploy/base`, the platform activates:

- Default-deny NetworkPolicy in all namespaces
- All LLM calls routed through local inference (no external API calls)
- Prompt injection guards enabled (11 regex patterns + control character sanitization)
- HMAC-SHA256 audit logging enabled
- All containers run as non-root with read-only root filesystems
- mTLS enforced between all services
- RBAC roles scoped to minimum required permissions
- Input validation on all API endpoints
- Token budgets active for all agents

No opt-in required. No "security mode" flag. No additional configuration.

---

## 2. Input Validation

**AlertPayload Schema Validation:**

Every incoming alert is validated against a strict JSON Schema before processing:

```go
// pkg/validation/alert_payload.go
type AlertPayloadValidator struct {
    schema *jsonschema.Schema
}

func (v *AlertPayloadValidator) Validate(payload []byte) error {
    var alert map[string]interface{}
    if err := json.Unmarshal(payload, &alert); err != nil {
        return ErrMalformedJSON
    }
    return v.schema.Validate(alert)
}
```

**Reject Rules:**
- Malformed JSON → rejected with 400
- Missing required fields (`id`, `title`, `severity`, `source`) → rejected
- Severity values outside enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) → rejected
- Field length exceeding limits (title: 512 chars, description: 4096 chars) → rejected
- Nested objects exceeding depth limit (5) → rejected
- Payload size exceeding 1MB → rejected

---

## 3. Prompt Injection Defense

**11 Regex Patterns + Control Character Sanitization + XML-Tag Wrapping:**

```go
// pkg/security/prompt_guard.go
var injectionPatterns = []regexp.Regexp{
    regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`),
    regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an)\s+`),
    regexp.MustCompile(`(?i)system\s*:\s*`),
    regexp.MustCompile(`(?i)assistant\s*:\s*`),
    regexp.MustCompile(`(?i)\[INST\]`),
    regexp.MustCompile(`(?i)<<SYS>>`),
    regexp.MustCompile(`(?i)```system`),
    regexp.MustCompile(`(?i)new\s+instruction`),
    regexp.MustCompile(`(?i)disregard\s+(all|any|previous)`),
    regexp.MustCompile(`(?i)act\s+as\s+if`),
    regexp.MustCompile(`(?i)forget\s+(all|everything|previous)`),
}
```

**Control Character Sanitization:**
- Strip all Unicode control characters (U+0000–U+001F, U+007F–U+009F)
- Normalize Unicode (NFKC normalization)
- Remove zero-width characters (ZWSP, ZWNJ, ZWJ)

**XML-Tag Wrapping:**
- User-supplied content wrapped in `<user_content>` tags
- System prompt isolated in `<system_instructions>` tags
- Agent output parsed only from expected XML sections

---

## 4. Rate Limiting

**Token Bucket Per Agent:**

```go
// pkg/ratelimit/token_bucket.go
type AgentRateLimiter struct {
    buckets map[string]*tokenbucket.Bucket
    mu      sync.RWMutex
}

// Defaults:
// - Triage Agent: 100 tokens/sec, burst 200
// - Analysis Agent: 50 tokens/sec, burst 100
// - Threat Intel Agent: 30 tokens/sec, burst 60
// - Response Agent: 20 tokens/sec, burst 40
```

**Purpose:** Prevent runaway LLM costs from:
- Compromised agent generating unbounded requests
- Feedback loops between agents
- Cascading retries on provider errors

---

## 5. Audit Trail

**HMAC-SHA256 Signed Entries:**

```go
// pkg/audit/hmac.go
type AuditEntry struct {
    Timestamp   time.Time `json:"timestamp"`
    AgentID     string    `json:"agent_id"`
    Action      string    `json:"action"`
    Input       string    `json:"input"`
    Output      string    `json:"output"`
    Confidence  float64   `json:"confidence"`
    ApprovedBy  string    `json:"approved_by,omitempty"`
    HMAC        string    `json:"hmac"`
}

func (e *AuditEntry) Sign(secret []byte) {
    payload := fmt.Sprintf("%s:%s:%s:%s:%s",
        e.Timestamp.Format(time.RFC3339Nano),
        e.AgentID, e.Action, e.Input, e.Output)
    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(payload))
    e.HMAC = hex.EncodeToString(mac.Sum(nil))
}
```

**Immutable Storage:**
- Log entries written to append-only storage
- Hash chain: each entry includes SHA-256 of previous entry
- Tamper detection: verify hash chain on read
- Customer can export and independently verify integrity

---

## 6. Secrets Management

**Vault Dynamic Credentials:**

```go
// pkg/secrets/vault.go
type VaultClient struct {
    client *api.Client
}

func (v *VaultClient) GetDynamicCredentials(role string) (*Credentials, error) {
    secret, err := v.client.Logical().Read("database/creds/" + role)
    if err != nil {
        return nil, err
    }
    return &Credentials{
        Username: secret.Data["username"].(string),
        Password: secret.Data["password"].(string),
        TTL:      secret.LeaseDuration,
    }, nil
}
```

**Rules:**
- No plaintext secrets in environment variables, ConfigMaps, or code
- All credentials sourced from HashiCorp Vault with dynamic leases
- Auto-rotation: credentials rotated before TTL expiry
- Audit log: every secret access logged with caller identity

---

## 7. Network Segmentation

**Default-Deny NetworkPolicy:**

```yaml
# deploy/network-policies/default-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: cobalto
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Namespace Isolation:**
- `cobalto-collection` — Alert ingestion, log forwarding
- `cobalto-processing` — Normalization, enrichment, deduplication
- `cobalto-analysis` — LLM inference, agent orchestration, RAG
- `cobalto-response` — Approval gates, response actions, notifications
- Each namespace has explicit NetworkPolicy allowing only required traffic

**mTLS:**
- All inter-service communication encrypted via Istio/Linkerd mTLS
- Certificate rotation automated via cert-manager
- No plaintext HTTP between services

---

## 8. Container Security

**Trivy Scanning:**

```yaml
# .github/workflows/security.yml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: cobalto/${{ matrix.service }}:${{ github.sha }}
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'
```

**Container Hardening:**
- All containers run as non-root (`runAsNonRoot: true`, `runAsUser: 1000`)
- Read-only root filesystem (`readOnlyRootFilesystem: true`)
- No privilege escalation (`allowPrivilegeEscalation: false`)
- Drop all capabilities; add only required ones
- No host network, host PID, or host IPC
- Resource limits enforced (CPU, memory)

---

## 9. IAM

**Least Privilege:**

```yaml
# deploy/rbac/agent-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agent-role
  namespace: cobalto-analysis
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
    resourceNames: ["agent-config"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "update"]
```

**IRSA for EKS:**
- No static AWS credentials
- IAM Roles for Service Accounts (IRSA) for S3, SQS, SNS access
- Each service account scoped to specific AWS resources
- No wildcard permissions

---

## 10. Principle-to-Implementation Mapping

| Principle | Implementation | Location |
|---|---|---|
| Security-by-Default | Zero-config secure deployment | `deploy/base/` |
| Input Validation | JSON Schema validation, reject malformed | `pkg/validation/alert_payload.go` |
| Prompt Injection Defense | 11 regex patterns, control chars, XML wrapping | `pkg/security/prompt_guard.go` |
| Rate Limiting | Token bucket per agent | `pkg/ratelimit/token_bucket.go` |
| Audit Trail | HMAC-SHA256 signed, immutable logs | `pkg/audit/hmac.go`, `pkg/audit/immutability.go` |
| Secrets Management | Vault dynamic credentials, auto-rotation | `pkg/secrets/vault.go` |
| Network Segmentation | Default-deny NetworkPolicy, namespace isolation, mTLS | `deploy/network-policies/` |
| Container Security | Trivy scanning, non-root, read-only FS | `.github/workflows/security.yml` |
| IAM | Least privilege, IRSA, no static creds | `deploy/rbac/` |
| Encryption | mTLS inter-service, TLS externally | `pkg/middleware/tls.go` |
| Vulnerability Management | Trivy in CI, admission controller in cluster | `deploy/admission-controller/` |
| Supply Chain Security | Signed images, SBOM generation, provenance | `.github/workflows/supply-chain.yml` |
