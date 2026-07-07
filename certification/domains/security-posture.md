# Security Posture Certification

> **Domain:** Platform self-protection — authentication, authorization, audit, injection prevention, secrets management  
> **Control Owner:** Auth Service Owner / Security Engineer  
> **Steady State:** All requests authenticated, all actions audited, zero prompt injection bypasses, secrets rotated on schedule

## Certification Scope

Certifies that the cobalto platform protects itself against the attacks it detects in client environments.

| Capability | Component | Security Control |
|-----------|-----------|-----------------|
| API Authentication | AuthMiddleware | HMAC constant-time X-API-Key comparison, no-keys warning mode |
| Console Authentication | console-auth | JWT login/verify/refresh/logout, bcrypt passwords, rate limiting |
| Audit Trail | AuditLogger | HMAC-SHA256 signed JSON entries, per-action granularity |
| Rate Limiting | RateLimiter | Token bucket per-agent, 60 req/min default |
| Input Validation | InputValidator | Pydantic schema lock, `additionalProperties: false` |
| Prompt Injection Guard | PromptInjectionGuard | Regex + ML two-layer detection |
| Secrets Management | Vault + ESO | Dynamic secrets, rotation policies, audit logging |
| Network Security | NetworkPolicy | Least-privilege egress/ingress per service |
| Container Security | securityContext | runAsNonRoot, readOnlyFS, cap drop ALL, seccomp |

## Steady State Definition

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Auth rejection rate | 100% of invalid API keys rejected | Auth middleware test |
| Auth false positive rate | 0% (valid keys always pass) | Integration test with valid key |
| Audit log completeness | Every request logged (except /health, /ready, /metrics) | Count requests vs. log entries |
| Rate limit enforcement | 100% of over-limit requests get 429 | Rate limiter test |
| Prompt injection detection | ≥ 97% of known patterns blocked | Injection guard test suite |
| Secret rotation adherence | 100% of secrets rotated within TTL | Vault audit log verification |
| Container non-root | 100% of containers run as non-root | K8s manifest validation |
| Network policy isolation | 0% cross-namespace traffic without explicit allow | Network policy review |

## Controls Under Certification

| Control ID | Control | Evidence | Test Procedure |
|-----------|---------|----------|---------------|
| SP-01 | API key authentication (HMAC constant-time) | Auth middleware test pass | `security-controls-test.sh` |
| SP-02 | No-keys warning mode (non-blocking) | Warning log on startup with no keys | CI log check |
| SP-03 | Console JWT auth (login, verify, refresh, logout) | E2E auth flow tests | `security-controls-test.sh` |
| SP-04 | Bcrypt password hashing (rounds ≥ 12) | Hash verification in E2E | `security-controls-test.sh` |
| SP-05 | Token rotation on refresh | E2E test: refresh invalidates old token | `security-controls-test.sh` |
| SP-06 | Rate limiting per agent (token bucket) | Rate limiter unit test | `security-controls-test.sh` |
| SP-07 | Audit log HMAC signing | Audit log verification script | `security-controls-test.sh` |
| SP-08 | Input validation schema lock | `test_additional_properties_rejected` | `security-controls-test.sh` |
| SP-09 | Prompt injection detection (regex + ML) | Injection guard test suite (10 patterns) | `security-controls-test.sh` |
| SP-10 | Vault dynamic secret rotation | Vault audit log verification | Manual query |
| SP-11 | Container securityContext enforcement | K8s manifest scan | CI `k8s-hardening` job |
| SP-12 | Network policy isolation | kubectl describe networkpolicy + audit | CI `k8s-hardening` job |

## Chaos Experiments

| Experiment | Hypothesis | Blast Radius |
|-----------|-----------|-------------|
| [Secret rotation](../../chaos/experiments/secret-rotation.md) | Vault PKI rotation during active load does not drop requests | Namespace |
| Token replay | Replayed JWT is rejected after refresh token rotation | Service |
| Rate limit bypass | Burst traffic above limit returns 429 and does not crash | Pod |

## Test Coverage Requirements

- **Auth middleware:** 100% branch coverage (keys present, keys missing, valid key, invalid key)
- **Console auth:** 100% of endpoints (login, verify, refresh, logout) in unit + E2E
- **Rate limiter:** Boundary tests (exactly at limit, 1 over, burst)
- **Audit logger:** All log levels (INFO, WARNING, ERROR) with HMAC verification
- **Prompt injection guard:** ≥ 40 known patterns + random fuzz
- **K8s hardening:** Every deployment/statefulset checked for securityContext

## Certification Procedure

```bash
# 1. Run auth + security tests
PYTHONPATH=services/langgraph-agent python3 -m pytest \
  tests/unit/test_auth.py tests/unit/test_middleware.py -v

# 2. Run injection guard tests
PYTHONPATH=services/langgraph-agent python3 -m pytest \
  tests/unit/ -k "test_injection_guard or test_input_validator" -v

# 3. Run E2E auth flow (requires cluster)
python3 -m pytest tests/e2e/test_auth_flow.py -v

# 4. Validate K8s hardening
bash scripts/validate-hardening.sh

# 5. Generate evidence
python3 certification/evidence/generate-package.py --domain security-posture
```

## Current Status

| Control | L1 (CI Gate) | L2 (Validation) | L3 (Evidence) | L4 (Audit) |
|---------|:-------------:|:----------------:|:--------------:|:-----------:|
| SP-01 | ✅ 12 tests | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-02 | ✅ Log check | ✅ Manual | ⏳ Template ready | ⏳ Planned |
| SP-03 | ✅ 11 E2E tests | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-04 | ✅ E2E hash check | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-05 | ✅ E2E refresh test | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-06 | ✅ 3 unit tests | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-07 | ✅ 35 log entries | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-08 | ✅ 2 integration tests | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-09 | ✅ 10/10 patterns | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-10 | ⏳ Manual only | ⏳ Pending | ⏳ Pending | ⏳ Planned |
| SP-11 | ✅ 15 deployments | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| SP-12 | ✅ 8 namespaces | ✅ Automated | ⏳ Template ready | ⏳ Planned |
