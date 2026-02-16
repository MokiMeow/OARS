# Risk Register

## Usage

Track priority risks, owners, mitigations, and deadlines.  
Update at least weekly during delivery and monthly in steady-state operations.

## Risk Table

| Risk ID | Risk Description | Category | Probability | Impact | Owner | Mitigation | Status | Target Date |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R-001 | Policy bypass vulnerability in connector path | Security | Medium | Critical | Security Lead | Enforce mandatory orchestrator mediation and mTLS; add blocking integration tests | Open | 2026-04-15 |
| R-002 | Receipt signing key compromise | Security | Low | Critical | Platform Security | KMS isolation, key rotation, anomaly detection, emergency re-key runbook | Open | 2026-03-30 |
| R-003 | Cross-tenant data leakage via query APIs | Architecture | Low | Critical | Backend Lead | Tenant-scoped query guards, row-level policies, abuse tests | Open | 2026-04-01 |
| R-004 | Approval workflow latency impacts critical ops | Reliability | Medium | High | SRE Lead | SLA queue prioritization and escalation tuning | Open | 2026-04-20 |
| R-005 | Incomplete evidence mapping for audits | Compliance | Medium | High | GRC Lead | Control mapping QA and completeness reports | Open | 2026-05-01 |
| R-006 | Performance bottleneck at receipt verification | Performance | Medium | High | Architecture Lead | Cache trust roots, optimize canonicalization, parallel verification | Open | 2026-05-10 |
| R-007 | Slow partner integration adoption | Go-to-market | Medium | Medium | Product Lead | SDKs, reference connectors, partner enablement program | Open | 2026-06-01 |

## Rating Scale

- Probability: `Low`, `Medium`, `High`
- Impact: `Medium`, `High`, `Critical`

## Required Fields For New Risks

- clear failure scenario
- measurable impact
- accountable owner
- mitigation and due date
- explicit close criteria

