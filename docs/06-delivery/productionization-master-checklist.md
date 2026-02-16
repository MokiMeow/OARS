# Productionization Master Checklist

Snapshot date: 2026-02-14

Purpose: close remaining gaps between (a) product + architecture docs and (b) implementation so OARS can be deployed as an enterprise-ready reference platform.

Status legend:

- `done`: implemented, tested, docs updated.
- `in_progress`: currently implementing.
- `pending`: not started.
- `infra_required`: requires external infrastructure or deployment topology beyond this repo's local runtime.

## Checklist

| ID | Area | Item | Status | Definition of Done |
| --- | --- | --- | --- | --- |
| PC-001 | API | Idempotency key support for mutating endpoints | done | `Idempotency-Key` enforced on `POST /v1/actions` with stored replay; mismatch returns conflict; tests cover same-key replay and mismatch behavior. |
| PC-002 | Receipts | Receipt verification accepts receipt payload + optional chain | done | `POST /v1/receipts/verify` supports verifying an arbitrary receipt payload using supplied public key(s) and optional chain data; tests cover signature verify with supplied key. |
| PC-003 | Receipts | Receipt search/query APIs | done | `GET /v1/receipts` supports tenant-scoped filtering by actor/tool/policy fields; tests cover basic filtering and tenant isolation. |
| PC-004 | Docs | Doc-code schema alignment strategy | done | Docs updated to reflect canonical request/response shape and compatibility strategy (camelCase canonical; snake_case accepted where necessary). |
| PC-005 | Policy | Context-rich matching (time/env/data-type) | done | Policy rules support additional contextual match fields and evaluation uses action context; tests cover match semantics. |
| PC-006 | Integration | MCP proxy mode | done | `/mcp` Streamable HTTP endpoint proxies upstream MCP tools via `OARS_MCP_UPSTREAMS`, converting calls into OARS actions; docs cover mapping + security; tests cover connector execution. |
| PC-007 | Integration | Embedded SDK | done | Published SDK package (or workspace module) that wraps action submission, idempotency, receipt verification, and retries; tests cover request shaping and auth headers. |
| PC-008 | Integration | Event-driven backplane mode | done | `OARS_BACKPLANE_MODE=queue` enqueues execution jobs and processes them via `src/worker/index.ts`; docker compose reference and docker-backed test cover end-to-end. |
| PC-009 | Ops | Real outbound alert routing integrations | done | Slack/PagerDuty/webhook delivery providers implemented; routing rules select channel IDs; delivery results are audited via security events; docs cover `OARS_ALERT_CHANNELS`. |
| PC-010 | Storage | Production persistence (DB/object storage) | done | Normalized Postgres-backed platform store available (`OARS_STORE=postgres`) with schema migrations and docker-backed integration test. |
| PC-011 | Security | Real mTLS service-to-service enforcement | done | TLS client-certificate mode available (`OARS_MTLS_MODE=tls`) with CA verification and trusted identities file support; docker compose reference included. |
| PC-012 | Compliance | Receipt queryability by control tags | done | Add a control-tag query model (explicit tagging or computed associations) and expose query endpoints; tests cover sample control filters. |

## Current Focus

- None (all checklist items are implemented for the reference deployment).
