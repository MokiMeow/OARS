# System Architecture

## High-Level Architecture

OARS is a control-plane and data-plane hybrid:

- Control plane: identity, policy, approvals, governance, tenant administration
- Data plane: action mediation, execution, receipt generation, telemetry emission

## Core Components

1. API Gateway
- Terminates TLS and enforces request limits.
- Routes to internal services.

2. Action Orchestrator
- Receives normalized action requests.
- Coordinates policy, approval, execution, and receipts.

3. Identity Service
- Resolves user/service identities and delegated claims.
- Issues internal subject tokens for trusted internal calls.

4. Policy Decision Point (PDP)
- Evaluates policy rules against contextual inputs.
- Returns decision and rationale with rule references.

5. Approval Service
- Manages approval workflows and state machines.
- Stores approval events and escalation actions.

6. Connector Runtime
- Executes approved actions against external systems.
- Applies connector-specific hardening and retries.

7. Receipt Service
- Emits cryptographically signed receipts at every state transition.
- Publishes receipts to ledger and event streams.

8. Ledger Store
- Append-only receipt/event persistence.
- Supports hash-chain linking and integrity checks.

9. Evidence Engine
- Builds evidence maps from receipts, policies, and control catalogs.
- Produces signed export bundles.

10. Observability Stack
- Metrics, logs, and traces.
- Security and reliability alert pipelines.

## Reference Request Flow

1. Client sends action request.
2. Identity service resolves actor chain.
3. PDP evaluates policy.
4. If approval required, approval service gates execution.
5. Connector runtime executes action.
6. Receipt service writes signed receipts.
7. Evidence and monitoring subsystems consume events.

## Deployment Topology

- Regional deployment with active-active control plane.
- Managed message bus for event propagation.
- Segregated data stores for policy, receipts, and analytics.
- Per-tenant encryption keys with centralized HSM/KMS management.

## Reliability Design

- Idempotent action handling using `action_id` and idempotency keys.
- Backpressure and queue-based retries for connectors.
- Circuit breakers for unstable downstream systems.
- Disaster recovery with cross-region backup and restore runbooks.

## Integration Modes

- MCP proxy mode for agent tool mediation.
- Direct SDK mode for custom runtime integration.
- REST API mode for systems without agent-native protocol support.

## Design Constraints

- All privileged actions require explicit policy decision.
- No unsigned action state is persisted.
- No shared tenant execution context.
- All service-to-service calls are mutually authenticated.

