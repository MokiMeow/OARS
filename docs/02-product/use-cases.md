# Use Cases And User Journeys

## Primary Users

- Security engineer
- GRC analyst
- AI platform engineer
- Application team lead
- Compliance auditor

## Use Case 1: Safe Agent Action Execution

Actor: AI platform engineer  
Goal: Ensure no agent action runs without policy evaluation.

Flow:

1. Agent submits action request to OARS gateway.
2. OARS resolves identity and delegation context.
3. Policy engine decides allow/deny/approve.
4. If allowed, execution broker calls target tool.
5. Receipt service emits state receipts.
6. Logs, metrics, and traces are correlated by action ID.

Success Criteria:

- Every action has an auditable receipt chain.
- Denied actions include exact policy rationale.

## Use Case 2: Approval For Sensitive Operations

Actor: Security team  
Goal: Require human approval for risky actions.

Flow:

1. Policy engine flags operation as approval-required.
2. Approval request is routed to designated approvers.
3. Approval or rejection is captured with identity, timestamp, and reason.
4. Execution proceeds only on valid approval state.
5. Final receipt links original request and approval decision.

Success Criteria:

- No bypass path exists for approval-required actions.
- Approval SLA breaches produce alerts.

## Use Case 3: Incident Investigation

Actor: Security operations  
Goal: Trace suspicious action from alert to actor and data impact.

Flow:

1. SOC receives anomaly alert with action ID.
2. Analyst fetches full receipt chain and policy context.
3. Analyst identifies delegated identity path.
4. Analyst exports signed investigation packet.

Success Criteria:

- Root-cause trail is complete and tamper-evident.
- Time to investigation is under predefined target.

## Use Case 4: Audit Evidence Generation

Actor: GRC analyst  
Goal: Produce audit evidence without manual spreadsheet assembly.

Flow:

1. Analyst selects framework and reporting period.
2. Evidence engine maps receipts and policies to controls.
3. System generates signed evidence package.
4. Auditor verifies package signatures and data lineage.

Success Criteria:

- Evidence generation is repeatable and deterministic.
- Missing control evidence is automatically flagged.

## Use Case 5: Multi-Tenant Enterprise Deployment

Actor: Enterprise admin  
Goal: Operate multiple business units with strict isolation.

Flow:

1. Admin creates tenant policies and key scopes.
2. Teams onboard their agent runtimes and tools.
3. OARS enforces tenant-specific policies and data boundaries.
4. Central team monitors fleet-level risk and reliability.

Success Criteria:

- Cross-tenant data access is impossible by design.
- Tenant-specific reporting and exports are available.

## Traceability

- Product requirements: `docs/02-product/product-requirements.md`
- Architecture: `docs/03-architecture/system-architecture.md`
- Security controls: `docs/04-security/security-architecture.md`

