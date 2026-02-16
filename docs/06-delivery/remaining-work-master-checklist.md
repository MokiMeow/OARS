# Remaining Work Master Checklist

## Snapshot

- Date: 2026-02-14
- Goal: close all gaps between current implementation and full v1 scope defined in product, architecture, security, compliance, and operations docs.

## Status Legend

- `done`: completed and validated with tests/docs.
- `in_progress`: currently being implemented.
- `pending`: not started.

## Checklist -- Original Scope (v1)

| ID | Workstream | Item | Status | Definition of Done |
| --- | --- | --- | --- | --- |
| RW-001 | Security | Tenant-scoped SIEM dead-letter operations | done | Dead-letter list/replay/resolve require tenant scope, tenant access enforced, tests cover mismatch and validation errors. |
| RW-002 | Security | Error model request correlation (`requestId`) | done | API error responses include request ID when supplied, tested in integration tests. |
| RW-003 | Ledger | Immutable append-only receipt/event storage | done | Replace mutable JSON state path for audit artifacts with append-only store and integrity verification APIs. |
| RW-004 | Ledger | Legal hold and retention policy controls | done | Tenant-level retention policy and legal hold APIs implemented with enforcement tests. |
| RW-005 | Policy | Policy rollback API and lifecycle audit completion | done | `rollback` endpoint + audited state transitions + tests for rollback correctness. |
| RW-006 | Policy | Policy simulation/dry-run mode | done | Non-mutating decision simulation endpoint returns decision/rationale without execution. |
| RW-007 | Approval | Multi-step approval chains (serial/parallel) | done | Approval workflow supports configurable stages and complete signed decision trail. |
| RW-008 | Approval | Approval SLA timers and escalation | done | Timers/escalations emit events/alerts and are covered by integration tests. |
| RW-009 | Approval | Step-up auth for critical approvals | done | High-risk approvals require stronger auth context and deny bypass paths. |
| RW-010 | Evidence | Evidence graph model and ingestion pipeline | done | Core runtime graph entities (`Action`, `Receipt`, `PolicyVersion`, `ApprovalDecision`, `Actor`) and relation ingestion pipeline are implemented. |
| RW-011 | Evidence | Control mapping registry + completeness scanning | done | Framework mappings managed in versioned registry; missing coverage detector operational. |
| RW-012 | Evidence | Signed evidence bundle generation hardening | done | Signed bundles include lineage hash list and independent verification flow. |
| RW-013 | Keys | Key lifecycle states and rotation workflow | done | Active/retiring/retired states, rotation endpoint, historical verification continuity. |
| RW-014 | Keys | Trust-root/public-key metadata endpoint | done | Verifiers can resolve historical public keys via API with versioned metadata. |
| RW-015 | Connectors | Connector library expansion | done | Add production-grade connectors beyond Jira/Slack/IAM with tests and risk metadata. |
| RW-016 | Connectors | Vault-backed secret isolation per connector | done | Connector credentials removed from plain state and fetched from secure secret provider abstraction. |
| RW-017 | Reliability | Backpressure and durable queue semantics | done | Retry and delivery paths provide durable queue behavior, bounded memory, and operational controls. |
| RW-018 | Reliability | Load/performance validation and SLO checks | done | Automated benchmarks for latency/throughput and regression thresholds in CI pipeline. |
| RW-019 | Reliability | Backup/restore automation and DR drills | done | Backup/restore jobs scripted and drill evidence documented per runbook cadence. |
| RW-020 | Security | mTLS and service-to-service identity hardening | done | Internal service calls enforce workload identity/mTLS in deploy topology. |
| RW-021 | Security | Encryption at rest and sensitive field protection | done | Sensitive fields encrypted/tokenized with key management integration. |
| RW-022 | Testing | Security test suite expansion | done | Add auth bypass fuzzing, tenant isolation regression matrix, and key-handling tests. |
| RW-023 | API | Tenant bootstrap and key rotation admin endpoints | done | Endpoints from API spec implemented and documented. |
| RW-024 | Ops | CI/CD, release gates, and deployment automation | done | Build/test/security gates and deployment rollback controls operational. |
| RW-025 | Ops | Operational dashboards and alert routing hardening | done | SLO dashboards and actionable on-call alert thresholds in place. |
| RW-026 | Adoption | Open spec + conformance suite publication artifacts | done | Public profile package with schema, compatibility policy, and conformance tests prepared. |
| RW-027 | Adoption | Multi-partner pilot execution evidence | done | Pilot evidence from at least 3 partners documented with success metrics. |

## Checklist -- Hardening & Quality (v1.1)

Items identified and implemented during deep code audit on 2026-02-14.

| ID | Workstream | Item | Status | Definition of Done |
| --- | --- | --- | --- | --- |
| RW-028 | Security | SQL injection bypass fix in database connector | done | Case-insensitive destructive SQL regex with comment stripping blocks `DROP`, `TRUNCATE`, `DELETE FROM`, `ALTER TABLE`, `GRANT`, `REVOKE` even when obfuscated with SQL comments. (`src/core/connectors/database-connector.ts`) |
| RW-029 | Security | API rate limiting middleware | done | Sliding-window per-token/IP rate limiter (default 300 rpm, configurable via `OARS_RATE_LIMIT_RPM`). Returns 429 with `x-ratelimit-limit` and `x-ratelimit-remaining` headers. Skips `/health`. (`src/api/server.ts`) |
| RW-030 | Security | Request body size limits | done | Fastify `bodyLimit` configured (default 1 MB, configurable via `OARS_BODY_LIMIT_BYTES`). Prevents large payload abuse. (`src/api/server.ts`) |
| RW-031 | Security | Comprehensive security response headers | done | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-XSS-Protection: 0` applied to all responses. (`src/api/server.ts`) |
| RW-032 | Security | CORS configuration | done | Configurable CORS origins via `OARS_CORS_ORIGINS` env var (comma-separated). Handles `OPTIONS` preflight. (`src/api/server.ts`) |
| RW-033 | Security | Dev token production hardening | done | `OARS_DISABLE_DEV_TOKENS=true` disables all dev tokens. Logs warning when dev tokens active in `NODE_ENV=production`. (`src/core/services/auth-service.ts`) |
| RW-034 | Security | SSRF protection hardening | done | Expanded `isForbiddenTarget()` blocks all private IPv4 ranges (10.x, 172.16-31.x, 192.168.x, 127.x), cloud metadata (169.254.x.x, metadata.google), IPv6 private (fd00::/8, fe80::/10), localhost variants. (`src/core/services/execution-service.ts`) |
| RW-035 | Reliability | Graceful shutdown with signal handling | done | SIGTERM/SIGINT handlers call `app.close()` for clean connection drain. Idempotent shutdown guard prevents double-close. (`src/index.ts`) |
| RW-036 | Testing | Policy service unit tests (18 tests) | done | Default policy evaluation, custom rule matching (toolIds, operations, riskTiers, environments), priority ordering, policy lifecycle CRUD, `decisionToState()` mapping. (`tests/policy-service.test.ts`) |
| RW-037 | Testing | Approval workflow unit tests (7 tests) | done | Pending creation, approve/reject decisions, unknown/duplicate decision errors, escalation scan, step-up requirement. (`tests/approval-service.test.ts`) |
| RW-038 | Testing | Evidence graph and compliance unit tests (5 tests) | done | Evidence graph snapshot/node listing, control mapping CRUD, framework filtering, coverage scanning. (`tests/evidence-compliance.test.ts`) |
| RW-039 | Testing | SIEM delivery unit tests (5 tests) | done | Generic webhook delivery, Splunk HEC auth headers, retry queue on failure, backpressure queue limits, empty status. (`tests/siem-delivery.test.ts`) |
| RW-040 | Testing | Backup/restore and ledger unit tests (6 tests) | done | Ledger append/verify, tamper detection (startup throw), tenant-filtered entries, backup catalog CRUD, default retention policy. (`tests/backup-ledger.test.ts`) |
| RW-041 | UI | Admin dashboard (command-center) | done | Self-contained HTML dashboard at `/dashboard` with dark theme. Sections: System Health, Live Actions, Alerts, Policies, Receipt verification, Ledger integrity, SIEM status, Tenants, Connectors. Auto-refresh, Bearer token auth, no CDN dependencies. (`src/api/dashboard.html`, route in `src/api/routes/public.ts`) |
| RW-042 | Architecture | Split monolithic server.ts into route modules | done | `src/api/server.ts` now acts as composition root; routes are split into `src/api/routes/*.ts` modules (`public.ts`, `auth.ts`, `tenants.ts`, `actions.ts`, `receipts.ts`, `policies.ts`, `evidence.ts`, `admin.ts`). |
| RW-043 | Docs | Update checklist with hardening items | done | This checklist updated with RW-028 through RW-043 reflecting all security, testing, UI, and architecture work. |

## Test Coverage Summary

| Metric | Before (v1) | After (v1.1+) |
| --- | --- | --- |
| Test files | 4 | 16 |
| Total tests | 43 | 102 (2 Docker-backed tests skipped by default) |
| Typecheck | clean | clean |

New test files added (v1.1 hardening + follow-on):
- `tests/policy-service.test.ts` -- 18 tests
- `tests/approval-service.test.ts` -- 7 tests
- `tests/evidence-compliance.test.ts` -- 5 tests
- `tests/siem-delivery.test.ts` -- 5 tests
- `tests/backup-ledger.test.ts` -- 6 tests
- `tests/api-hardening.test.ts` -- 4 tests (rate limiting, CORS, headers, body limit)
- `tests/ssrf-protection.test.ts` -- 1 test (sandbox target blocking)
- `tests/database-connector-security.test.ts` -- 6 tests (comment-obfuscated destructive SQL blocking)
- `tests/service-identity-service.test.ts` -- trusted identities file loading
- `tests/backplane-file.test.ts` -- file-backed backplane driver behavior
- `tests/backplane-postgres-api.test.ts` -- queue mode end-to-end (Docker-backed)
- `tests/mcp-connector.test.ts` -- MCP connector upstream execution

## New Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `OARS_RATE_LIMIT_RPM` | `300` | Max requests per minute per token/IP |
| `OARS_BODY_LIMIT_BYTES` | `1048576` | Max request body size (1 MB) |
| `OARS_CORS_ORIGINS` | (none) | Comma-separated allowed CORS origins |
| `OARS_DISABLE_DEV_TOKENS` | `false` | Set `true` to disable all dev tokens in production |
| `OARS_STORE` | `file` | Store mode (`file` or `postgres`) |
| `OARS_POSTGRES_URL` | (none) | Postgres connection string for `OARS_STORE=postgres` |
| `OARS_BACKPLANE_MODE` | `inline` | Execution mode (`inline` or `queue`) |
| `OARS_BACKPLANE_DRIVER` | `postgres` | Backplane driver (`postgres` or `file`) |
| `OARS_BACKPLANE_LOCK_TIMEOUT_SECONDS` | `60` | Reclaim running jobs after this timeout |
| `OARS_BACKPLANE_MAX_ATTEMPTS` | `1` | Max attempts before dead-letter |
| `OARS_BACKPLANE_RETRY_DELAY_SECONDS` | `15` | Delay before retrying a failed job |
| `OARS_MCP_UPSTREAMS` | (none) | JSON array of MCP upstream servers (`id`, `url`, optional `headers`) |
| `OARS_MCP_ALLOW_PRIVATE_NETWORK` | `false` | Allow private-network upstream URLs |
| `OARS_MCP_TOOL_CACHE_TTL_SECONDS` | `300` | MCP tool list cache TTL |
| `OARS_MCP_ALLOWED_ORIGINS` | (none) | Optional Origin allowlist for `/mcp` |
| `OARS_MTLS_TRUSTED_IDENTITIES_FILE` | (none) | File path to trusted workload identities JSON |
| `OARS_MTLS_MODE` | `header` | Workload identity mode (`header` or `tls`) |
| `OARS_TLS_CERT_PATH` | (none) | TLS server certificate (PEM) |
| `OARS_TLS_KEY_PATH` | (none) | TLS server private key (PEM) |
| `OARS_MTLS_CA_PATH` | (none) | CA bundle for validating client certs (PEM) |

## Execution Order

### Phase 1 -- Original Scope (complete)

1. Security and isolation hardening (`RW-001`, `RW-002`, `RW-020`, `RW-021`, `RW-022`).
2. Immutable ledger and key lifecycle (`RW-003`, `RW-004`, `RW-013`, `RW-014`).
3. Policy + approval maturity (`RW-005` to `RW-009`).
4. Evidence/compliance engine completion (`RW-010` to `RW-012`).
5. Reliability/operations completion (`RW-017` to `RW-019`, `RW-024`, `RW-025`).
6. Connector expansion + standardization rollout (`RW-015`, `RW-016`, `RW-026`, `RW-027`).

### Phase 2 -- Hardening & Quality (v1.1)

1. Critical security fixes (`RW-028` SQL injection, `RW-034` SSRF).
2. API hardening (`RW-029` rate limiting, `RW-030` body limits, `RW-031` headers, `RW-032` CORS).
3. Production hardening (`RW-033` dev tokens, `RW-035` graceful shutdown).
4. Test expansion (`RW-036` to `RW-040`) -- 41 new tests across 5 files.
5. Admin dashboard (`RW-041`).
6. Architecture cleanup (`RW-042`) -- done.

## Current Focus

- Active implementation track: v1.1 hardening complete (15 of 15 items done).
- Remaining: none.
- Next milestone: production deployment readiness review.
