# Threat Model

## Scope

This threat model covers OARS control plane, data plane, connectors, and administrative interfaces.

## Assets

- policy definitions and decision logs
- signed receipts and receipt chain integrity
- approval records and actor identity trails
- tenant configuration and key material
- connector credentials and execution context

## Adversaries

- External attacker with API access attempts
- Insider misuse with legitimate credentials
- Compromised agent runtime
- Compromised connector or downstream integration

## Threat Categories

1. Spoofing
- Forged identity tokens.
- Compromised service credentials.

Mitigations:

- strict token validation, issuer/audience checks
- short-lived tokens and rotation
- mTLS service identity enforcement

2. Tampering
- Receipt payload modification.
- Policy edits without authorization.

Mitigations:

- signature verification and hash-chain checks
- immutable append-only stores
- signed policy publication events

3. Repudiation
- User denies initiating an action.
- Approver denies authorization step.

Mitigations:

- actor chain capture with immutable timestamps
- signed approval records
- auditable session metadata

4. Information Disclosure
- Leakage of sensitive tool payloads.
- Excessive visibility across tenants.

Mitigations:

- data minimization and redaction policy
- field-level encryption and scoped retrieval
- tenant-scoped authorization boundaries
- fail-closed startup behavior when encrypted payloads exist without configured decryption key

5. Denial Of Service
- Flooding policy or gateway endpoints.
- Connector abuse causing backpressure collapse.

Mitigations:

- rate limits and quotas
- workload isolation and queue buffering
- circuit breakers and adaptive throttling

6. Elevation Of Privilege
- Agent escalates to admin-equivalent operations.
- Approval bypass via workflow manipulation.

Mitigations:

- explicit deny rules on privileged operations
- separate admin plane identities
- immutable approval state machine transitions

## High-Risk Abuse Cases

- Agent performs mass data exfiltration via approved connector.
- Insider modifies policy to silently permit restricted actions.
- Attacker forges receipts for false audit evidence.

## Detection Requirements

- Unusual action volume or timing by agent ID
- Policy drift and unauthorized publication attempts
- Repeated denied actions targeting privileged resources
- Receipt chain break anomalies

## Residual Risk Management

- Maintain prioritized risk register in `docs/09-governance/risk-register.md`
- Execute quarterly threat model reviews
- Run red-team and chaos security exercises twice yearly
