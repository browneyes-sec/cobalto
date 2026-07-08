# RS-02: In-Memory State Persistence

## Context
The agent time-series counters and metric accumulators currently use in-memory data structures (Python dicts). On service restart, all accumulated data is lost. This affects alert trend analysis, rate-limit counters, and audit trail persistence.

## Rationale
1. **Dev environment**: No guarantee of persistent volume mounts. Restarts are frequent during development.
2. **Complexity**: Persistent checkpointing requires Redis/SQLite integration with proper serialization, locking, and recovery — not warranted at current scale.
3. **Dependency**: The orchestration layer (LangGraph) manages conversation state externally; the counters in question are auxiliary (rate limiting, statistics).
4. **Observability**: Prometheus scrapes provide durable metric storage; audit logs are written synchronously and can be redirected to stdout/file.

## Outcome
Accepted for development. In-memory counters reset on restart. This is documented and classified as acceptable risk.

## Mitigations
- Rate limit counters reset is benign (limits reapply after restart).
- Audit log entries are synchronous and survive restart (output to stdout captured by Docker).
- Prometheus scrapes provide durable metric history.

## Production Path
- **Phase 1**: Persist counter snapshots to Redis with TTL-based expiry.
- **Phase 2**: Implement WAL-backed checkpointing for audit trail continuity.
- **Phase 3**: Add `GET /admin/state` diagnostic endpoint for dump/restore.

## Tags
- resilience
- state-management
- dev-acceptable
- technical-debt

## Author
cert-agent (2026-07-08)
