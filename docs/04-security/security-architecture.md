# Security Architecture

## Security Goals

- Prevent unauthorized agent actions.
- Ensure end-to-end integrity of action history.
- Limit blast radius for compromised agents or connectors.
- Provide high-fidelity forensic data for investigations.

## Control Layers

1. Identity Controls
- OIDC authentication for users/admins.
- Mutual TLS and workload identity for services.
- Scoped OAuth tokens for delegated agent actions.

2. Access Controls
- RBAC for platform administration.
- ABAC for runtime action authorization.
- Explicit deny precedence for high-risk operations.

3. Data Security Controls
- TLS 1.3 for all network transport.
- AES-256 at rest for databases/object storage.
- Field-level encryption for sensitive values.
- Secret management via KMS/HSM-backed vaulting.
- Encrypted payload persistence for sensitive runtime fields (action inputs, security event payloads, evidence payload nodes) via configurable data protection key.

4. Execution Controls
- Policy evaluation before execution.
- Connector allowlists per tenant.
- Request/response validation and sanitization.
- Runtime egress controls and domain allowlists.

5. Integrity Controls
- Cryptographic receipt signing.
- Hash-chain verification.
- Key rotation with historical trust continuity.

6. Monitoring Controls
- Security event stream for all policy and approval decisions.
- Detection rules for privilege escalation and unusual action velocity.
- SIEM integrations for centralized triage.

## Identity And Delegation Model

Actor chain model:

- `human actor`: initiating identity
- `agent identity`: autonomous runtime principal
- `service identity`: execution path identity

Each action receipt stores complete chain for non-repudiation.

## Key Management

- Tenant-scoped key material for signing and encryption.
- Key lifecycle states: active, retiring, retired.
- Periodic rotation and emergency rotation runbook.
- Public trust metadata endpoint for verification clients.

## Tenant Isolation

- Logical isolation for policy and config.
- Data partitioning by tenant keyspaces.
- Access enforcement at API, service, and storage layers.

## Secure SDLC Requirements

- Mandatory threat modeling for net-new features.
- Static and dynamic application security testing.
- Dependency vulnerability scanning with release gates.
- Security review sign-off for production rollout.

## Security Acceptance Criteria

1. Unauthorized action attempts are denied and receipted.
2. Signed receipts fail verification after tampering.
3. Tenant cross-access attempts are blocked and alerting is triggered.
4. Incident timeline reconstruction is possible from receipt and telemetry data.
5. Sensitive persisted payload values are not stored in plaintext when encryption key is configured.
