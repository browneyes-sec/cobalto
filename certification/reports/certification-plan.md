# Certification Completion Plan — Handover to Certifier

**Author**: fullstack (pabl0wsl)
**Date**: 2026-07-07
**Target**: 100% control coverage → defend certification gate

## Current State

| Metric | Value |
|--------|-------|
| Total controls | 62 |
| ✅ Pass | 33 (53%) |
| ⚠️ Warn | 8 (13%) |
| ❌ Fail | 0 |
| ⏭ Skipped | 8 (13%) |
| ⏳ Planned | 13 (21%) |
| **Coverage** | **49/62 (79%)** |

## Gap Classification

Gaps fall into 4 tiers based on effort-to-impact. **Tier 1 and Tier 2** together bring coverage to **95%** (59/62) with <1 day of work.

---

## TIER 1 — Quick Wins (0 code changes, just generate evidence)

These controls already work — they just need evidence JSON artifacts generated.

| # | Control | What it verifies | How to prove |
|---|---------|-----------------|-------------|
| 1 | **PE-10** | CPU metric `process_cpu_seconds_total` exposed | Query `/metrics`, record value, assert < 1.0 core |
| 2 | **SC-11** | No secrets in agent logs | `docker logs` + grep for `API_KEY`, `SECRET`, `PASSWORD`, `TOKEN` |
| 3 | **SC-14** | `/metrics` does not leak secrets | Curl `/metrics`, grep for credential patterns |
| 4 | **OB-03** | Metric label cardinality is correct | Parse `/metrics`, verify each `cobalto_*` family has expected label keys |
| 5 | **OB-04** | Audit logs are structured JSON | Parse each log line with `json.loads()`, assert > 80% parse rate |

**Evidence**: Generate 5 HMAC-signed JSON files in `certification/evidence/pipeline/`.
**Effort**: ~15 minutes.

---

## TIER 2 — Small Code Changes (1-2 files, < 30 min each)

| # | Control | Problem | Fix |
|---|---------|---------|-----|
| 6 | **SC-15** | No CORS middleware in `main.py` | Add `from fastapi.middleware.cors import CORSMiddleware` + `app.add_middleware()` with production origins |
| 7 | **SC-10** | `PromptInjectionGuard` exists in `middleware/` but is never called in the request pipeline | Wire it into `_run_agent_pipeline()` — call `guard.wrap_for_prompt()` on `raw_log` before passing to agent |
| 8 | **SC-04/05** | Rate limiter works (token bucket) but test at 60 RPM doesn't trigger with 3-10 curls | Either: (a) lower `RATE_LIMIT_PER_MINUTE` in `.env` to 5 for testing, OR (b) send 100 rapid requests via loop |
| 9 | **SC-08** | HMAC secret in code is `"change-me-in-production"` but stored signatures may use a different key | Either: (a) verify and document the actual HMAC_SECRET in production config, OR (b) regenerate evidence with the correct key |
| 10 | **SC-01/02/03** | Auth returns 422 (validation) instead of 401/403 — `COBALTO_DISABLE_AUTH=true` in dev | Either: (a) set `COBALTO_API_KEY` in `.env` and restart, OR (b) accept that auth is dev-disabled and document as design decision |

**Evidence**: Code changes + re-run security procedure + generate evidence.
**Effort**: ~1-2 hours total.

---

## TIER 3 — Medium Effort (new code or tests, half-day each)

| # | Control | Problem | Fix |
|---|---------|---------|-----|
| 11 | **PE-04/05/06** | Tool latency histogram exists but only system-level calls are instrumented | Add `@metrics.instrument_tool("tool_name")` decorator to OpenCTI, TheHive, Cortex call sites in the agent graph |
| 12 | **PE-11** | No concurrent load test in procedures | Write k6 script: 50 VUs burst over 30s, measure p95 latency and error rate |
| 13 | **SC-06** | Rate limiter window reset not tested | After hitting 429, wait 60s (or test with low RPM), verify 200 response. Add to security-controls-test.sh |
| 14 | **OB-06** | Grafana running but no provisioned dashboards | Create `grafana/dashboards/agent-overview.json` with panels for: latency heatmap, alert rate, errors, token usage. Provision via Grafana API or dashboard configmap |

**Evidence**: Code + provisioned dashboards + re-run procedures.
**Effort**: ~1-2 days total.

---

## TIER 4 — Infrastructure / New Feature (multi-day)

| # | Control | Problem | Fix |
|---|---------|---------|-----|
| 15 | **RS-04/05** | No circuit breaker — agent crashes when Qdrant/OpenCTI are down | Add `tenacity` retry decorator with circuit breaker pattern to all external tool calls. Fall back to rule-based triage when dependencies are unavailable |
| 16 | **RS-06** | No OOM protection — no memory limits in docker-compose.yml | Add `mem_limit: 512m` and `mem_reservation: 256m` to langgraph-agent service |
| 17 | **RS-09/10** | Endurance test not run — need 100+ alert cycles | Write `endurance-test.sh`: send 100 alerts at 1/sec, check memory stable + metric cardinality stable. Needs ~2 min runtime |
| 18 | **SC-12/13** | K8s securityContext — requires K8s cluster | Deploy to staging cluster, add `securityContext` to Helm templates, verify with `kube-bench` |

**Evidence**: Code + config + deployment + endurance run.
**Effort**: ~1 week total.

---

## Prioritization for Certification Gate

### Phase 1 (Today — 79% → 87%)
Tiers 1 + 2 = 5 quick evidence + 5 small fixes = 10 controls resolved:

1. PE-10 → generate CPU evidence ✅
2. SC-11 → generate no-secrets evidence ✅
3. SC-14 → generate /metrics-clean evidence ✅
4. OB-03 → generate label cardinality evidence ✅
5. OB-04 → generate JSON log evidence ✅
6. SC-15 → add CORS middleware (1 import, 5 lines)
7. SC-10 → wire PromptInjectionGuard (3 lines in main.py)
8. SC-04/05 → fix rate limit test procedure
9. SC-08 → document/propagate HMAC secret
10. SC-01/02/03 → decide auth strategy or document dev-mode decision

### Phase 2 (This week — 87% → 95%)
Tier 3 = 4 medium-effort controls:

11. PE-04/05/06 → instrument tool decorators
12. PE-11 → k6 concurrency script
13. SC-06 → rate limiter reset test
14. OB-06 → Grafana dashboard provisioning

### Phase 3 (Next sprint — 95% → 100%)
Tier 4 = 4 infrastructure controls:

15. RS-04/05 → circuit breaker
16. RS-06 → OOM limits
17. RS-09/10 → endurance test
18. SC-12/13 → K8s security

---

## Handoff Checklist for Certifier

1. **Read the evidence schema**: `certification/evidence/README.md` — HMAC-signed JSON format
2. **Use existing procedure scripts** as templates:
   - `certification/procedures/performance-benchmark.sh`
   - `certification/procedures/pipeline-integrity-test.sh`
   - `certification/procedures/security-controls-test.sh`
   - `certification/procedures/compliance-evidence-test.sh`
3. **Tier 1 is pure evidence generation** — use `curl` + `openssl dgst -sha256 -hmac` against the running service
4. **Tier 2 edits are in `services/langgraph-agent/main.py`** — add middleware imports and wiring
5. **Always test with `curl -sf` first** before generating evidence
6. **Evidence artifacts go in `certification/evidence/pipeline/<CONTROL>_<TIMESTAMP>.json`**
7. **Update `certification/traceability/control-to-evidence-matrix.md`** after each control
8. **Commit with conventional commit**: `feat(certification): <control-id> <status> — <summary>`
9. **Never push directly** — create PR for certifier review

## Critical Warnings

- **HMAC secret**: `settings.HMAC_SECRET` defaults to `"change-me-in-production"`. If the audit logger uses a different key, signatures won't verify. Either align or document.
- **Auth is disabled in dev**: `COBALTO_DISABLE_AUTH=true`. SC-01/SC-02 return 422 not 401. This is intentional for dev but must flip in staging.
- **Rate limiter is 60 RPM default**: Sending 3 slow curls won't trigger it. Use `RATE_LIMIT_PER_MINUTE=5` env var or a loop of 100 rapid requests.
- **Lazy metrics**: `cobalto_*` metrics only appear in `/metrics` AFTER first alert is processed. Send a valid alert before collecting metric evidence.
- **Prometheus `up` query quirk**: `up{job="langgraph-agent"}` returns 2 results (one for `:8080`, one for `:8080` service). Use `up{job="langgraph-agent",instance="langgraph-agent:8080"}` to get the real agent status.
