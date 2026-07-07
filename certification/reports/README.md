# Certification Reports

> Certification status reports organized by domain and audit package.  
> Reports are auto-generated from evidence artifacts.

## Report Types

| Type | Frequency | Audience | Content |
|------|-----------|----------|---------|
| **Weekly Certification Summary** | Weekly | Engineering team | Control status changes, new regressions, experiment results |
| **Domain Certification Report** | Per domain completion | Control Owner | All controls in domain, evidence references, exceptions |
| **Audit Evidence Package** | Pre-audit | External Auditor | All evidence artifacts, traceability matrices, chain of custody |
| **Continuous Compliance Dashboard** | Real-time | CISO / Compliance Lead | Live control status, trend charts, SLA adherence |

## Report Index

| # | Report | Date | Status | Key Findings |
|---|--------|------|--------|-------------|
| | _No reports yet — certification program launched July 2026_ | | | |

## Report Generation

```bash
# Generate weekly summary
python3 certification/reports/generate-report.py \
  --type weekly \
  --output certification/reports/weekly-$(date +%Y-%m-%d).md

# Generate domain certification report
python3 certification/reports/generate-report.py \
  --type domain \
  --domain security-posture \
  --output certification/reports/domain-security-posture.md

# Package for audit
python3 certification/reports/generate-report.py \
  --type audit-package \
  --framework soc2 \
  --output certification/reports/audit-packages/soc2-$(date +%Y-%m-%d).zip
```

## Report Template

### Weekly Certification Summary

```markdown
# Certification Summary — Week of YYYY-MM-DD

## Overview
- **Controls certified:** N/62 (N%)
- **New certifications:** --
- **Regressions:** --
- **Experiments run:** --

## Changes This Week
| Control | Previous | Current | Change |
|---------|----------|---------|--------|
| XX-NN | ⏳ Pending | ✅ Certified | New evidence procedure |

## Regressions
| Control | Previous | Current | Root Cause | Remediation |
|---------|----------|---------|------------|-------------|
| -- | -- | -- | -- | -- |

## Chaos Experiments
| Experiment | Result | Observations |
|------------|--------|-------------|
| Pod failure | ✅ PASS | Recovery within 25s |
| Network partition | ✅ PASS | Graceful degradation confirmed |

## Action Items
- [ ] Complete pending control XX-NN by EOW
- [ ] Investigate performance regression in PF-01
```

## Storage

All reports are stored in this directory (`certification/reports/`) and committed to the repository for version-controlled audit trail.
