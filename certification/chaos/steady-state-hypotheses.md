# Steady State Hypotheses

> Observable metrics that define "normal" for each certification domain.  
> Every chaos experiment measures pre-, during-, and post-experiment metrics against these baselines.

## Domain: Pipeline Integrity

### Normal State
- `POST /agent/analyze` returns HTTP 200 for valid payloads
- Response body contains all `AgentResult` fields
- Response time p50 < 1.2s, p95 < 5.0s in CI environment
- No error entries in audit log for valid requests
- `alert_id` uniqueness maintained

### Hypothesis Template
```yaml
Given: The pipeline is processing LOW-severity alerts at < 20 req/s
When: [injection] is applied to [component]
Then: [expected outcome] occurs
And: The system returns to steady state within [duration]
```

## Domain: Security Posture

### Normal State
- `GET /agent/analyze` with invalid API key returns HTTP 401
- `POST /agent/analyze` with valid key returns HTTP 200
- `POST /api/auth/login` with valid creds returns JWT in < 500ms
- Audit log entries have valid HMAC-SHA256 signatures
- Rate limiter returns 429 past threshold

### Hypothesis Template
```yaml
Given: Auth middleware is enforcing API key validation
When: [attack] is attempted against [auth component]
Then: [expected rejection] occurs
And: The audit log contains a corresponding entry
```

## Domain: Resilience

### Normal State
- `kubectl get pods` shows all pods in `Running` state
- Liveness probes return HTTP 200 within 5s
- Readiness probes return HTTP 200 within 5s
- Alert processing continues during pod rollout (zero dropped)
- Dependency failures produce degraded (non-error) responses

### Hypothesis Template
```yaml
Given: All services are healthy and processing alerts
When: [failure] is injected into [component]
Then: [degradation behavior] occurs
And: Full functionality resumes within [duration] of failure removal
```

## Domain: Performance

### Normal State
- k6 benchmarks within 20% of baseline for all metrics
- CPU utilization < 80% under 20 VU load
- Memory utilization < 80% under sustained load
- No HTTP 429 responses under normal load
- No HTTP 5xx responses under any load

### Hypothesis Template
```yaml
Given: The system is under [VU] load with [pattern] traffic
When: [load change] is applied
Then: [latency/throughput impact] is observed
And: Metrics return to baseline within [cool-down period]
```

## Domain: Compliance

### Normal State
- Audit log entries exist for all requests (except exempted paths)
- Evidence artifacts are HMAC-signed and verifiable
- Control-to-evidence mapping is 100% complete
- No compliance control gaps detected in automated scan

### Hypothesis Template
```yaml
Given: The system is operating with [compliance framework] controls enabled
When: [event] occurs
Then: [evidence artifact] is generated
And: The artifact is verifiable via [verification method]
```

## Domain: Data Governance

### Normal State
- All data stores are configured with AES-256 encryption at rest
- All service-to-service connections use TLS 1.3
- PII fields in audit logs are masked (not plaintext)
- Vault PKI certificates have < 24h remaining TTL before rotation
- Data retention policies are enforced within configured window

### Hypothesis Template
```yaml
Given: [data store] contains [classification] data
When: [event] affecting the data occurs
Then: [governance control] is enforced
And: [evidence] of enforcement is logged
```
