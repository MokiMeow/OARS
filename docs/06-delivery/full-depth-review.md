# Full Depth Review (Docs vs Implementation)

Snapshot date: 2026-02-14

This document answers:

1. What was built in this repository (and how it works).
2. Whether it is "fully complete" relative to the repo's documentation.
3. What security and production-readiness gaps remain.

## What We Built

OARS in this repo is a single-process TypeScript Fastify API (`src/api/server.ts`) with a set of in-process services. It implements a governance control plane for agent actions:

- Policy-before-execution for tool requests
- Multi-stage approvals for risky actions
- Signed, hash-chained receipts for every action state transition
- Immutable append-only ledger storage for receipts and security events
- Evidence graph + control mapping + signed evidence bundles
- SCIM sync for tenant members and roles
- SIEM delivery adapters with retry, dead-lettering, and durability
- Vault-backed secrets for connector execution constraints
- Backup/restore automation with DR drill evidence reports
- Workload identity guard for service-role tokens (mTLS proxy header enforcement)
- Ops dashboard + alert routing configuration store

Data persistence is local-file based (JSON and NDJSON) under `data/` by default.

## How It Works (End-to-End Flow)

### 1) Request Authentication + Authorization

- All `/v1/*` endpoints require `Authorization: Bearer <token>`.
- Tokens can be static dev tokens or JWTs (HS256 internal; RS256 via trusted JWKS providers).
- Each request is scope-checked (e.g., `actions:write`) and tenant access is enforced by claim membership (`tenantIds[]`).
- If `OARS_MTLS_ENABLED=true`, service-role tokens must also present trusted workload identity headers (see "Workload Identity Guard").

### 2) Action Submission

Endpoint: `POST /v1/actions`

Pipeline:

1. Normalize request into an `ActionRecord`.
2. Evaluate risk (`RiskService`) and policy (`PolicyService`).
3. Emit receipt `action.requested`.
4. If policy returns:
   - `deny`: mark action `denied`, emit receipt `action.denied`, emit alert, emit security event.
   - `quarantine`: mark action `quarantined`, emit receipt `action.quarantined`, emit alert, emit security event.
   - `approve`: create approval record, emit receipt `action.approval_required`.
   - `allow`: continue directly to execution.
5. Execute via connector (`ExecutionService` + `ConnectorRegistry`), sanitize basic secret keys in output.
6. Emit receipt `action.executed` or `action.failed`.
7. Emit alert for high-risk executed actions and failures.

### 3) Approvals

Endpoint: `POST /v1/approvals/:approvalId/decision`

- Approval workflows can be multi-stage (`serial` or `parallel` quorum).
- Critical approvals require step-up authentication (`OARS_APPROVAL_STEP_UP_SECRET`).
- Escalations are scanned by `POST /v1/admin/approvals/escalations/scan`.

### 4) Receipts and Verification

- Receipts are canonicalized and signed with tenant-scoped Ed25519 keys.
- Receipts are hash-chained per action (`prevReceiptHash`).
- Verification endpoint: `POST /v1/receipts/verify` verifies signature and chain continuity.
- Public key metadata: `GET /v1/trust/tenants/:tenantId/keys` provides public keys for independent verification.

### 5) Immutable Ledger

- Receipts and security events are appended to `data/immutable-ledger.ndjson` (configurable).
- Each ledger entry includes a chained hash referencing the previous entry.
- Admin APIs allow status, listing by tenant, and integrity verification.
- Tenant retention + legal hold is enforced via governance APIs.

### 6) Security Events + SIEM

- Most major operations emit `SecurityEventRecord`.
- Events are forwarded to configured SIEM targets (webhook, Splunk HEC, Datadog logs, Sentinel Log Analytics).
- Reliability features include durable retry queue persistence and dead-letter persistence with replay/resolve APIs.

### 7) Evidence + Compliance

- Receipts and bundle exports are ingested into an evidence graph (nodes + edges).
- Control mappings define required node types per framework (EU AI Act, ISO 42001, SOC2).
- Coverage scan detects missing evidence types required by mapped controls.
- Exports produce signed evidence bundles with verification API.

### 8) Secrets and Data Protection

- Connector secrets are stored in a vault file (`VaultSecretService`) encrypted at rest (AES-GCM).
- Sensitive persisted payload fields in state storage are encrypted at rest via `DataProtectionService` when `OARS_DATA_ENCRYPTION_KEY` is set.
- If encrypted payloads exist but the encryption key is not configured, startup fails (fail-closed).

### 9) Backup / Restore / DR Drills

- Backup manifests snapshot key local artifacts with checksums.
- Restore validates artifact checksum and writes files back, returning `restartRequired: true`.
- DR drill runs a backup + checksum validation + parses staged state + verifies staged ledger integrity, persisting a JSON drill report.

### 10) Ops Dashboard + Alert Routing

- Ops dashboard endpoint aggregates action/alert/security-event counts and shows SIEM, workload identity, and backup status.
- Alert routing rules are stored and audited and can be enforced via configured outbound channels (Slack webhooks, PagerDuty Events v2, generic webhooks) using `OARS_ALERT_CHANNELS`.
- Delivery is best-effort and recorded as security events (`alert.delivered` / `alert.delivery_failed`); for strict delivery guarantees, run delivery through an async queue (see `PC-008`).

## Workload Identity Guard (mTLS)

Implementation is a "proxy attestation guard", not real TLS termination:

- When enabled, `service` role tokens must present:
  - `x-oars-mtls-subject`
  - `x-oars-mtls-fingerprint`
  - optionally (if `OARS_MTLS_ATTESTATION_SECRET` set):
    - `x-oars-mtls-issued-at`
    - `x-oars-mtls-signature` (HMAC over subject + fingerprint + issued-at)

This only provides a meaningful security boundary if these headers are injected by a trusted upstream (e.g., a TLS-terminating proxy) and stripped from external clients.

## Are We "Fully Complete"?

### Checklist Completion

The engineering checklist in `docs/06-delivery/remaining-work-master-checklist.md` is marked complete (RW-001 through RW-027) and validated by:

- `npm run typecheck`
- `npm test`
- `npm run conformance`
- `npm run release:gate`

### Full Documentation Completion (Strict)

If "fully complete" means "every statement in product + architecture docs is implemented as written", then the answer is: not fully.

The current implementation is complete for the RW checklist scope and provides a strong end-to-end control-plane skeleton, but the broader documentation contains additional expectations that are not fully realized in this codebase.

## Gaps / Mismatches vs Docs (Important)

1. API naming conventions mismatch.
   - Docs frequently use `snake_case` fields (`tenant_id`, `receipt_id`) but implementation uses `camelCase` (`tenantId`, `receiptId`).
   - Compatibility: action submission now accepts `snake_case` aliases; canonical form remains `camelCase`.

2. Idempotency.
   - Docs specify `Idempotency-Key` and retry-safe behavior; `POST /v1/actions` now supports stored idempotent replay and rejects same-key mismatches.

3. Receipt verification API contract mismatch.
   - Receipt spec describes verifying arbitrary receipt payload + trust root; `POST /v1/receipts/verify` now supports verifying by stored `receiptId` or by arbitrary `receipt` payload using supplied public key material.

4. Receipts queryability.
   - Product requirements require querying receipts by actor/tool/policy/control tags; `GET /v1/receipts` supports tenant-scoped filtering by actor/tool/policy fields and can query by compliance control tags via `framework` + `controlId` (control mappings may define `receiptFilters`).

5. Policy model depth.
   - Product requirements call for time/environment/data-type contextual rules; rule matching now supports `environments`, `requiredDataTypes`, and `timeWindowUtc` (UTC hours, wrap-around supported) in addition to tool/operation/target substring/risk tier.

6. Integration patterns not implemented.
   - MCP proxy and event-driven backplane are described but not implemented in this repository. SDK embedded integration is implemented as an embedded TypeScript SDK (`src/sdk/*`).

7. Alert routing enforcement.
   - Outbound alert delivery is implemented for Slack/PagerDuty/webhook channels, but delivery is best-effort (no durable delivery queue yet).

8. Production NFRs not met by design.
   - The file-backed single-process design cannot satisfy multi-region durability, no-data-loss under zone failure, or high-throughput requirements without replacing storage/runtime architecture.

## Security Posture (What Is Strong vs What Is Not)

Strong (within this codebase):

- Tenant access checks on most tenant-scoped endpoints.
- Scoped permissions + role enforcement for administrative writes.
- Signed receipts + hash-chains + immutable ledger verification.
- Step-up approvals for critical operations.
- Dead-letter/retry durability for SIEM delivery.
- Fail-closed behavior when encrypted payloads exist but key is missing.

Not production-grade yet (needs external infrastructure changes):

- Static dev tokens and default secrets are not safe for production.
- Workload identity is header-based; requires a trusted proxy and strict header stripping.
- Key material (signing keys) is stored on disk without KMS/HSM protection.
- Storage is local files; no replication, no transactional guarantees, no access control at storage layer.

## Recommendation: "v1 Complete" vs "Production Complete"

- "RW checklist complete" is true.
- "Production-ready per product NFRs" is not true without re-platforming persistence, implementing idempotency, expanding policy model, adding real mTLS, and adding observability tooling.

If you want, the next step is to create a new "Productionization Checklist" that covers the non-RW doc gaps above and implement those items explicitly (rather than conflating them into RW-021..027).
