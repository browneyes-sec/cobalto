# Roles & Responsibilities

> RACI matrix for certification activities.  
> **R** = Responsible, **A** = Accountable, **C** = Consulted, **I** = Informed

## Core Roles

| Role | Description | Assignment |
|------|-------------|-----------|
| **Certification Authority** | Owns the certification program, approves scope changes, signs off on certification reports | Platform Lead / CISO |
| **Certification Engineer** | Designs and implements certification procedures, maintains evidence pipeline, runs chaos experiments | Platform Engineer |
| **Control Owner** | Responsible for a specific control domain (e.g., pipeline integrity, security posture) | Service Owner |
| **Evidence Custodian** | Maintains evidence artifacts, ensures immutability and chain of custody | DevOps Engineer |
| **Chaos Engineer** | Designs, reviews, and executes chaos experiments; maintains steady-state hypotheses | SRE / QA Engineer |
| **Auditor (Internal)** | Reviews evidence packages, validates control assertions, recommends certification levels | Security Engineer |
| **Auditor (External)** | Third-party certification audit — SOC 2, FedRAMP, etc. | External Assessor |

## RACI Matrix

### By Activity

| Activity | Cert Authority | Cert Engineer | Control Owner | Evidence Custodian | Chaos Engineer | Internal Auditor |
|----------|:-------------:|:-------------:|:-------------:|:-----------------:|:--------------:|:----------------:|
| Define certification scope | **A** | **R** | C | I | C | C |
| Write domain certification plan | I | **A/R** | C | I | C | C |
| Design chaos experiments | I | C | C | I | **A/R** | C |
| Execute certification procedures | I | **A/R** | **R** | C | **R** | I |
| Collect and sign evidence | I | C | **R** | **A/R** | I | I |
| Compare against baseline | I | **A/R** | I | C | C | I |
| Generate certification report | C | **R** | C | C | C | **A** |
| Approve certification level | **A** | **R** | I | I | I | C |
| Trigger recertification | **A** | **R** | C | I | C | C |

### By Domain

| Domain | Control Owner | Primary Cert Engineer | Chaos Engineer |
|--------|:-------------:|:--------------------:|:--------------:|
| Pipeline Integrity | LangGraph Agent Owner | Platform Engineer | SRE |
| Security Posture | Auth Service Owner | Security Engineer | Security Engineer |
| Resilience | DevOps / SRE | Platform Engineer | SRE |
| Performance | Platform Engineer | Platform Engineer | SRE |
| Compliance | Compliance Lead | Security Engineer | Security Engineer |
| Data Governance | Infrastructure Owner | DevOps Engineer | SRE |

## Responsibility Statements

### Certification Authority
- Approves the annual certification plan
- Signs certification reports after internal review
- Decides on exception requests (controls that cannot be fully certified)
- Authorizes recertification events
- Liaises with external auditors

### Certification Engineer
- Authors and maintains certification domain documents
- Implements certification test procedures as CI scripts
- Integrates chaos experiments into the CI pipeline
- Maintains the evidence generation toolchain
- Tracks certification metric trends over time

### Control Owner
- Implements and maintains the control in their service
- Provides domain expertise during experiment design
- Reviews experiment results for false positives
- Remediates certification failures
- Signs off on control certification within their domain

### Evidence Custodian
- Maintains the evidence storage system (immutable S3 bucket + signed artifacts)
- Validates evidence integrity (hash verification, signature checks)
- Manages evidence retention lifecycle
- Provides evidence access to auditors with chain-of-custody logs

### Chaos Engineer
- Authors steady-state hypotheses for each domain
- Designs experiments following the standardized template
- Reviews blast radius before execution
- Analyzes experiment results for systemic weaknesses
- Automates experiments for CI execution

## Escalation Path

```
Control Owner → Certification Engineer → Certification Authority
                        ↓
              Internal Auditor (compliance impact)
                        ↓
              External Auditor (if evidence package affected)
```
