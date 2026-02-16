# Enterprise Deployment Checklist

This checklist covers the remaining work needed to deploy OARS as a multi-instance enterprise service. These items require external infrastructure and deployment topology choices.

## Infra/Topology Requirements

1. Production persistence (PC-010)
- Implemented reference: `OARS_STORE=postgres` normalized store with schema migrations (see `docker-compose.postgres.yml` and `tests/postgres-api.test.ts`).
- For production: use managed Postgres, enforce backups, and set `OARS_DATA_ENCRYPTION_KEY`.

2. Real mTLS enforcement (PC-011)
- Implemented reference: `OARS_MTLS_MODE=tls` with TLS client cert verification and trusted identity file loading (see `docker-compose.mtls.yml` and `docs/07-operations/mtls.md`).
- For production: terminate/enforce mTLS at ingress/service mesh (or directly in OARS) and bind service-role tokens to workload identity.

3. MCP proxy mode (PC-006)
- Implemented reference: `/mcp` Streamable HTTP endpoint that converts MCP tool calls into OARS actions and executes upstream MCP tools via the `mcp` connector (see `docs/03-architecture/mcp-proxy.md`).
- For production: configure upstream servers via `OARS_MCP_UPSTREAMS` and run with `OARS_MTLS_MODE=tls` where service tokens are used.

4. Event-driven backplane (PC-008)
- Implemented reference: Postgres-backed execution job queue + worker entrypoint (see `docker-compose.backplane.yml`, `src/worker/index.ts`, and docker-backed test `tests/backplane-postgres-api.test.ts`).
- For production: scale worker replicas and tune retry/lock parameters; use an external queue if required by your topology.

5. Outbound alert routing providers (PC-009)
- Configure outbound alert delivery channels (Slack webhooks, PagerDuty Events v2, generic webhooks) via `OARS_ALERT_CHANNELS`.
- Validate end-to-end in staging with escalation and retry semantics (for strict guarantees, route delivery through a durable queue per `PC-008`).

## Verification Before Production

- Run `docs/04-security/security-verification-checklist.md`.
- Run `npm run release:gate` and validate `npm audit --audit-level=high`.
- Validate tenant isolation with a staging tenant matrix.
- Validate receipt verification externally using only `GET /v1/trust/tenants/:tenantId/keys` and `POST /v1/receipts/verify`.
