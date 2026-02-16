# Integration Patterns

## Purpose

Provide standardized approaches to integrate OARS with diverse agent and enterprise environments.

## Pattern 1: MCP Proxy Integration

When to use:

- Existing MCP servers and agent clients already deployed.

How it works:

1. Agent client sends tool call through OARS MCP proxy.
2. OARS performs identity, policy, and approval handling.
3. OARS forwards approved call to target MCP server.
4. Receipts and telemetry are emitted for each state transition.

Benefits:

- Fast adoption with minimal runtime code changes.

## Pattern 2: SDK Embedded Integration

When to use:

- Custom agent runtime where direct SDK insertion is feasible.

How it works:

1. Application embeds OARS SDK.
2. SDK wraps action submission and receipt tracking.
3. Policy and approval outcomes are consumed inline.

Benefits:

- Fine-grained control and lower per-call overhead.
- Implementation: see `docs/03-architecture/sdk.md`.

## Pattern 3: API Gateway Mediation

When to use:

- Non-agent systems require action governance.

How it works:

1. System posts action requests to OARS REST API.
2. OARS performs full governance flow.
3. External system receives decision and action state updates.

Benefits:

- Uniform governance for legacy or mixed environments.

## Pattern 4: Event-Driven Backplane

When to use:

- High-volume asynchronous workloads.

How it works:

1. Action requests are enqueued.
2. OARS workers evaluate policy and execute connectors asynchronously.
3. State updates are published to event bus topics.

Benefits:

- Higher throughput and fault isolation.

## Integration Hardening Checklist

- Enforce mTLS between OARS and connector endpoints.
- Use scoped tokens and least privilege.
- Configure idempotency keys for retried actions.
- Register connector capability metadata and risk tiers.
- Validate payload schemas at ingress and egress.
