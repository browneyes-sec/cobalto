# Security Domain — Controls SC-01 through SC-15

**Steady-State Hypothesis**: All security middleware (auth, rate limiting, audit, injection guard, input validation) enforces controls consistently across every request.

## Controls

| ID | Control | Verification | Procedure |
|----|---------|-------------|-----------|
| SC-01 | Authentication rejects requests without API key | HTTP 401 when X-API-Key is missing | security-controls-test.sh |
| SC-02 | Authentication rejects invalid API key | HTTP 401 with invalid key | security-controls-test.sh |
| SC-03 | Authentication accepts valid API key | HTTP 200 with valid key | security-controls-test.sh |
| SC-04 | Rate limiter rejects requests over threshold | HTTP 429 after exceeding RPM limit | security-controls-test.sh |
| SC-05 | Rate limiter allows requests under threshold | HTTP 200 within RPM limit | security-controls-test.sh |
| SC-06 | Rate limiter resets after window | HTTP 200 after waiting for reset | security-controls-test.sh |
| SC-07 | Audit logger HMAC signs entries | Entry contains valid hmac_signature | security-controls-test.sh |
| SC-08 | Audit logger tamper detection works | verify_signature() returns false after tampering | security-controls-test.sh |
| SC-09 | Input validation rejects malformed payload | HTTP 422 with schema violation | security-controls-test.sh |
| SC-10 | Prompt injection guard blocks attack patterns | HTTP 422 with injection detection | security-controls-test.sh |
| SC-11 | No secrets in environment logs | Audit log does not contain secrets | security-controls-test.sh |
| SC-12 | K8s securityContext enforces non-root | Container runAsNonRoot=true | security-controls-test.sh |
| SC-13 | K8s securityContext enforces read-only FS | Container readOnlyRootFilesystem=true | security-controls-test.sh |
| SC-14 | /metrics endpoint does not expose secrets | Metrics output contains no credentials | security-controls-test.sh |
| SC-15 | CORS headers restrict origins | Response includes CORS headers | security-controls-test.sh |

## Steady-State Verification
- Service is running with `COBALTO_API_KEY` set
- Rate limiter is configured with known RPM
- HMAC secret is configured
