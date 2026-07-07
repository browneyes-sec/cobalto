# Pipeline Integrity Certification

> **Domain:** Data pipeline — alert ingestion, processing, storage, and retrieval  
> **Control Owner:** LangGraph Agent Service Owner  
> **Steady State:** Zero alerts lost, zero duplicates, HMAC receipts verifiable for all processed alerts

## Certification Scope

Certifies that the alert processing pipeline (Wazuh → LangGraph Agent → Response → Documentation) preserves data integrity at every stage.

| Stage | Component | Integrity Control |
|-------|-----------|------------------|
| Ingestion | POST /agent/analyze | Pydantic input validation, `additionalProperties: false`, alert_id uniqueness |
| Processing | LangGraph agent graph | Immutable state threading, no in-place mutation of alert payload |
| Enrichment | threat_intel_agent | IOC enrichment results stored as new keys, original alert preserved |
| Response | response_agent | Response actions logged with HMAC receipt linking to alert_id |
| Storage | final_state | Complete state dump including all intermediate results |
| Retrieval | AgentResult response | Full incident report with traceability back to original alert |

## Steady State Definition

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Alert loss rate | 0% (no alerts dropped between ingestion and response) | Compare ingress count vs. completion count |
| Duplicate detection | 0% (no duplicate alert_ids within retenion window) | alert_id uniqueness check |
| HMAC receipt verifiability | 100% (every processed alert has a verifiable receipt) | Receipt verification script |
| Input validation rejection | 100% of malformed payloads rejected with 422 | Integration test coverage |
| Schema adherence | 100% of fields conform to AlertPayload schema | Pydantic validation in middleware |

## Controls Under Certification

| Control ID | Control | Evidence | Test Procedure |
|-----------|---------|----------|---------------|
| PI-01 | Input validation rejects malformed payloads | 422 responses for invalid fields | `security-controls-test.sh` |
| PI-02 | Schema lock prevents extra fields | rejection of `malicious_field` | integration test `test_additional_properties_rejected` |
| PI-03 | Alert deduplication by alert_id (within window) | Rejection or merge of duplicate IDs | `pipeline-integrity-test.sh` |
| PI-04 | HMAC receipt generated for every tool call | Receipt in audit log | `pipeline-integrity-test.sh` |
| PI-05 | State machine preserves original alert | final_report references alert_id | integration test |
| PI-06 | Pipeline completes on known pathways | AgentResult with all expected fields | integration tests |
| PI-07 | Error paths produce logged failures | Audit entry with error context | integration tests |
| PI-08 | Alert ordering preserved within session | Sequential processing | Custom test |

## Chaos Experiments

| Experiment | Hypothesis | Blast Radius |
|-----------|-----------|-------------|
| [Data corruption](../../chaos/experiments/data-corruption.md) | Pipeline rejects malformed JSON fields without crashing | Pod |
| [API degradation](../../chaos/experiments/api-degradation.md) | External API timeouts produce enrichment_failed status, not data loss | Service |
| [Pod failure](../../chaos/experiments/pod-failure.md) | In-flight alerts are retried or visible in dead-letter queue after pod restart | Pod |

## Test Coverage Requirements

- **Unit tests:** ≥ 90% coverage of `main.py`, `middleware/validator.py`, `state.py`
- **Integration tests:** Every graph node executes at least once; all error paths exercised
- **E2E tests:** Full pipeline from POST to AgentResult with valid payloads
- **Fuzz tests:** Malformed, empty, oversized, and Unicode injection payloads

## Certification Procedure

```bash
# 1. Run unit + integration tests
make test-coverage

# 2. Run pipeline-specific integration tests
PYTHONPATH=services/langgraph-agent python3 -m pytest tests/integration/test_api.py -v

# 3. Run pipeline integrity experiment
./certification/procedures/pipeline-integrity-test.sh

# 4. Generate evidence
python3 certification/evidence/generate-package.py --domain pipeline-integrity
```

## Current Status

| Control | L1 (CI Gate) | L2 (Validation) | L3 (Evidence) | L4 (Audit) |
|---------|:-------------:|:----------------:|:--------------:|:-----------:|
| PI-01 | ✅ Tested (11 assertions) | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| PI-02 | ✅ Tested | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| PI-03 | ⏳ Pending | ⏳ Pending | ⏳ Pending | ⏳ Planned |
| PI-04 | ✅ Tested (HMAC audit) | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| PI-05 | ✅ Tested (integration) | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| PI-06 | ✅ Tested (113 tests) | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| PI-07 | ✅ Tested (error states) | ✅ Automated | ⏳ Template ready | ⏳ Planned |
| PI-08 | ⏳ Pending | ⏳ Pending | ⏳ Pending | ⏳ Planned |
