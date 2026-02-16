# Governance Model

## Purpose

Define how architectural, security, and standardization decisions are made and enforced.

## Governance Bodies

1. Product Steering Committee
- Owns roadmap priorities and release gates.

2. Architecture Review Board
- Owns architecture decisions and technical standards.

3. Security Council
- Owns security posture, exceptions, and risk acceptance.

4. Compliance Council
- Owns control mappings and audit-readiness posture.

## Decision Types

- Product scope decisions
- Architecture and interface decisions
- Security exception approvals
- Compliance control mapping changes

## Decision Process

1. Proposal submitted using ADR template.
2. Impact and risk analysis attached.
3. Relevant council reviews and votes.
4. Decision logged and versioned.
5. Implementation and verification tracked.

## Mandatory Decision Records

- Schema changes
- Policy language changes
- Cryptographic algorithm changes
- Multi-tenant data boundary changes
- Evidence model changes

## Escalation Rules

- Any unresolved SEV1 risk escalates to executive sponsor.
- Any compliance blocker escalates to steering committee within 48 hours.
- Any security exception longer than 30 days requires renewal approval.

## Meeting Cadence

- Weekly architecture and security review
- Bi-weekly delivery governance review
- Monthly compliance and audit readiness review

## Artifacts

- Decision log: `docs/09-governance/decision-log.md`
- Risk register: `docs/09-governance/risk-register.md`
- ADR template: `docs/templates/adr-template.md`

