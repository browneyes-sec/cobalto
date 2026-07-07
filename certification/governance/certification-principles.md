# Certification Principles

> Ten axioms governing all certification activities. Derived from TOGAF architecture principles and chaos engineering first principles.

## 1. Continuous Validation Over Point-in-Time Audits

Certification is not a snapshot. Every control must be verifiable on every commit. Static evidence packages are secondary to automated CI gates.

**Rationale:** SOC 2 Type II requires sustained control effectiveness over time. A control that works on audit day but fails the rest of the year is worse than useless.

**Measure:** Every certification control has a CI test that runs on `main` push.

## 2. Steady State Before Hypothesis

A system cannot be certified unless its normal behavior is measurable. Define the steady state *before* designing experiments.

**Rationale:** Chaos engineering principle #1. Without a steady state definition, you cannot detect regressions.

**Measure:** Each domain document contains explicit steady-state metrics with thresholds.

## 3. Blast Radius Proportional to Confidence

Experiments start at pod scope and escalate only after lower-level controls pass. Never run a namespace-level experiment before pod-level ones pass.

**Rationale:** Minimize production risk while building confidence incrementally.

**Measure:** Blast radius matrix in `chaos/blast-radius-matrix.md` governs experiment progression.

## 4. Evidence Is Code

All certification evidence must be generated programmatically, not collected manually. Manual evidence is suspect evidence.

**Rationale:** The platform is software-defined security operations. Its certification must match that paradigm.

**Measure:** Evidence generation scripts produce machine-readable artifacts (JSON schema, signed logs, hash-verified reports).

## 5. Defense in Depth for Certification Itself

The certification toolchain must be as hardened as the platform:
- Evidence signing prevents tampering
- CI pipeline for certification has separate, restricted credentials
- Certification artifacts are stored immutably

**Rationale:** An attacker who compromises the certification pipeline can fabricate evidence.

## 6. Regression Gates Over Feature Gates

A feature that causes a certification regression is blocked even if it passes functional tests. Performance and resilience are first-class requirements.

**Rationale:** In a SOC platform, a 500ms latency regression can cause missed detections.

## 7. Traceability from Control to Evidence

Every certified control must map to a specific evidence artifact with a verifiable chain of custody. No orphan controls.

**Rationale:** Auditors require a direct line from "what you claim" to "how you prove it."

## 8. Environments Must Be Comparable

Certification results in CI (kind cluster) must be correlatable to production. Differences must be documented and their impact assessed.

**Rationale:** A control that passes in CI but would fail in production is a certification gap.

## 9. Recertification Is Event-Driven, Not Calendar-Driven

Certification expires on material change, not on a fixed date. Triggers: dependency version bumps, infrastructure topology changes, security incident.

**Rationale:** Calendar-driven recertification is wasteful for a CI/CD-native platform. Event-driven ensures coverage where it matters.

## 10. Open Source, Open Evidence

All certification plans, procedures, and results are publicly available under the same license (Apache 2.0). Security-sensitive evidence (e.g., specific secret hashes) is redacted but the methodology is transparent.

**Rationale:** Open-source security platform → open-source certification. Transparency builds trust.
