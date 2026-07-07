---
name: Performance Regression
about: Report a detected performance regression from benchmark CI
title: '[PERF] '
labels: ['performance', 'regression']
assignees: ''
---

## Regression Details

| Metric | Current | Baseline | Change |
|--------|---------|----------|--------|
| _p95 latency_ | _ms_ | _ms_ | _+%_ |
| _failure rate_ | _%_ | _%_ | _+%_ |

**Test:** <!-- e.g., alert_ingestion, auth_burst -->
**Commit:** <!-- SHA that triggered the regression -->
**Run:** <!-- Link to GitHub Actions run -->

## Analysis

<!-- What changed since the last passing baseline? -->

## Reproduction

```bash
COBALTO_BENCHMARK_URL=http://localhost:8000 \
  ./scripts/run-benchmarks.sh --test <test_name>
```

## Possible Causes

- [ ] Code change in hot path
- [ ] External service degradation
- [ ] Infrastructure change
- [ ] Baseline drift (expected, update baseline)

## Action Items

- [ ] Root cause identified
- [ ] Fix applied
- [ ] Baseline updated
- [ ] CI re-run passes
