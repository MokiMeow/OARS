# Product Requirements

## Scope

This document defines full platform scope for OARS v1.

## Product Modules

1. Agent Gateway
- Normalizes inbound agent action requests from MCP, API, and connector adapters.
- Applies authn/authz and policy checks before execution.

2. Identity And Delegation
- Supports OIDC login for users and service identities.
- Supports OAuth delegation for agent-on-behalf-of flows.
- Stores actor chain for each action (`user -> agent -> tool`).

3. Policy Engine
- Supports allow, deny, approve, and quarantine decisions.
- Supports contextual rules (data type, environment, risk score, time, tenant).
- Supports dry-run mode for policy rollout.

4. Approval Workflows
- Multi-step approvals for high-risk actions.
- SLA timers and escalation policies.
- Approval evidence linked into receipts.

5. Execution Broker
- Executes approved actions via tool connectors.
- Enforces output sanitization and response policy checks.
- Handles retries with idempotency keys.

6. Receipt Service
- Creates signed receipts for requested, approved, denied, executed, and failed states.
- Supports receipt verification API and export.
- Supports hash-chaining for tamper evidence.

7. Ledger Storage
- Immutable event store for receipts and policy decisions.
- Supports tenant-level data segregation.
- Supports retention policies and legal hold.

8. Detection And Alerting
- Real-time detection rules for anomaly and abuse patterns.
- Alert routing to SIEM, ticketing, and on-call channels.

9. Compliance Evidence Engine
- Maps receipts to predefined control frameworks.
- Generates evidence bundles by time range, system, policy, and control objective.
- Supports signed exports.

10. Admin And Tenant Management
- Multi-tenant workspace management.
- RBAC and scoped permissions.
- SSO and SCIM provisioning.

## Functional Requirements

`FR-01` Action mediation is mandatory before every tool execution.  
`FR-02` Every action state transition emits a signed receipt.  
`FR-03` Receipts are queryable by actor, tool, policy, and control tags.  
`FR-04` Policy changes are versioned and auditable.  
`FR-05` Approval workflows support serial and parallel approvers.  
`FR-06` Receipt verification works without access to internal private keys.  
`FR-07` Evidence bundles can be generated without manual data stitching.  
`FR-08` Tenant isolation is enforced at data and policy layers.  
`FR-09` Admin APIs support full lifecycle automation.  
`FR-10` Platform emits telemetry for all critical flows.

## Non-Functional Requirements

- Availability: `99.95%` control-plane availability.
- Receipt durability: no data loss under single-zone failure.
- Throughput: sustain `>= 5,000` action requests/minute per region baseline.
- Latency: p95 policy decision latency `< 150ms` for cached policies.
- Security: encryption in transit and at rest, least privilege, key rotation.
- Observability: structured logs, metrics, tracing with correlation IDs.

## Out Of Scope For v1

- Autonomous policy generation by LLM.
- Fully offline deployment in disconnected environments.
- Marketplace billing and third-party rev-share.

## Acceptance Criteria

1. End-to-end execution flow works for approved, denied, and failed actions.
2. Receipts are signed and independently verifiable.
3. High-risk actions are blocked without approval.
4. Evidence pack generation covers at least three compliance frameworks.
5. SLO dashboards and alerting are active in production.

