# OARS Platform

OARS is a production platform for governing, auditing, and standardizing AI agent actions across enterprise systems.

The platform delivers:

- policy enforcement for agent actions
- signed, tamper-evident action receipts
- delegated identity and access control for agents
- compliance evidence automation for audits and regulatory programs

## Repository Goal

This repository is organized as an execution-ready documentation base for building OARS end-to-end, not as an MVP.

## Documentation Index

- `docs/README.md`
- `docs/01-strategy/vision.md`
- `docs/02-product/product-requirements.md`
- `docs/02-product/use-cases.md`
- `docs/03-architecture/system-architecture.md`
- `docs/03-architecture/receipt-specification.md`
- `docs/03-architecture/api-specification.md`
- `docs/03-architecture/integration-patterns.md`
- `docs/03-architecture/sdk.md`
- `docs/04-security/security-architecture.md`
- `docs/04-security/threat-model.md`
- `docs/04-security/security-verification-checklist.md`
- `docs/05-compliance/compliance-mapping.md`
- `docs/05-compliance/evidence-operations.md`
- `docs/06-delivery/full-build-plan.md`
- `docs/06-delivery/work-breakdown.md`
- `docs/06-delivery/testing-strategy.md`
- `docs/06-delivery/implementation-status.md`
- `docs/06-delivery/remaining-work-master-checklist.md`
- `docs/06-delivery/full-depth-review.md`
- `docs/06-delivery/productionization-master-checklist.md`
- `docs/07-operations/operations-manual.md`
- `docs/07-operations/runbooks.md`
- `docs/07-operations/runbooks/backup-restore-validation.md`
- `docs/07-operations/dr-drill-evidence-log.md`
- `docs/07-operations/container-deployment.md`
- `docs/07-operations/enterprise-deployment-checklist.md`
- `docs/08-adoption/standardization-playbook.md`
- `docs/08-adoption/pilot-program.md`
- `docs/08-adoption/pilot-evidence.md`
- `docs/09-governance/governance-model.md`
- `docs/09-governance/decision-log.md`
- `docs/09-governance/risk-register.md`
- `open-spec/oars-profile-v1.json`
- `open-spec/compatibility-policy.md`
- `open-spec/conformance-suite.md`

## Core Product Definition

OARS runs between agents and enterprise systems.

It provides:

1. Action mediation and policy checks before execution.
2. Approval workflows for risky operations.
3. Signed receipts for every approved, denied, or failed action.
4. Immutable receipt storage and verification APIs.
5. Real-time monitoring, alerting, and evidence packaging.

## Build Principles

- Security by default.
- Auditability by construction.
- Vendor-neutral interoperability.
- Strong operational reliability.
- Compliance automation as an output, not an afterthought.

## Local Run

```bash
npm install
npm run dev
```

API base URL: `http://localhost:8080`

Environment: see `.env.example` for the recommended variables (especially for production secrets).

## Docker

```bash
docker compose up --build
```

Note: the provided compose files set `NODE_ENV=development` for local use. In production (`NODE_ENV=production`),
you must provide non-development secrets (see **Auth** / runtime config).

Postgres-backed store:

```bash
docker compose -f docker-compose.postgres.yml up --build
```

Useful commands:

- `npm run typecheck`
- `npm test`
- `npm run security:check`
- `npm run build`
- `npm run perf:smoke`
- `npm run conformance`
- `npm run release:gate`
- `npm run test:docker` (runs Postgres-backed integration tests; requires Docker Engine)
- `npm run backup:create -- --reason="scheduled_backup"`
- `npm run backup:restore -- --backupId=<backup_id> --reason="restore_rehearsal"`
- `npm run backup:drill -- --reason="quarterly_drill"`

## SDK

An embedded TypeScript SDK is available as a package subpath export. See `docs/03-architecture/sdk.md`.

## Auth

All `/v1/*` endpoints require `Authorization: Bearer <token>`.

Mutating endpoints may accept `Idempotency-Key` to safely replay requests.

Default dev tokens:

- `dev_admin_token`
- `dev_operator_token`
- `dev_auditor_token`

In production (`NODE_ENV=production`), dev tokens are disabled by default. To explicitly allow them (not recommended),
set `OARS_ALLOW_DEV_TOKENS_IN_PRODUCTION=true`.

You can override token config with `OARS_API_TOKENS` (JSON array).

Example:

```bash
curl -X GET "http://localhost:8080/v1/connectors" -H "Authorization: Bearer dev_admin_token"
```

If `OARS_MTLS_ENABLED=true`, `service`-role tokens must present a workload identity. Supported modes:

- `OARS_MTLS_MODE=header` (legacy): clients (or a trusted mTLS-terminating proxy) must forward headers:
  - `x-oars-mtls-subject`
  - `x-oars-mtls-fingerprint`
  - when attestation secret is configured: `x-oars-mtls-issued-at`, `x-oars-mtls-signature`
- `OARS_MTLS_MODE=tls` (recommended): run the API with TLS client certificates enabled. OARS derives the same headers
  from the verified TLS peer certificate and overwrites any presented header values.

See `docker-compose.mtls.yml` for a self-contained local reference.

## Contributing / Security

- Contributing guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`

Runtime config:

- `OARS_ALLOWED_TOOLS` comma-separated connector allowlist (example: `jira,slack`)
- `OARS_ALERT_CHANNELS` JSON array of outbound alert channels (`generic_webhook`, `slack_webhook`, `pagerduty_events_v2`)
- `OARS_ALERT_WEBHOOK_URL` legacy single-channel alert webhook sink (mapped as `legacy_alert_webhook`)
- `OARS_SIEM_WEBHOOK_URL` optional security event webhook sink
- `OARS_SIEM_FILE_PATH` optional newline-delimited JSON event file path
- `OARS_SIEM_TARGETS` JSON array of SIEM targets (`generic_webhook`, `splunk_hec`, `datadog_logs`, `sentinel_log_analytics`)
- `OARS_SIEM_RETRY_AUTO_START` auto-start SIEM retry scheduler (`true`/`false`)
- `OARS_SIEM_RETRY_INTERVAL_SECONDS` retry interval
- `OARS_SIEM_RETRY_MAX_ATTEMPTS` max retry attempts per event/target
- `OARS_SIEM_RETRY_QUEUE_PATH` persistent SIEM retry queue file path
- `OARS_SIEM_RETRY_MAX_QUEUE_SIZE` max in-memory/persisted retry queue size before backpressure drops
- `OARS_JWT_SECRET` signing secret for JWT access tokens
- `OARS_JWT_ISSUER` JWT issuer value (default `oars.local`)
- `OARS_JWT_AUDIENCE` JWT audience value (default `oars-api`)
- `OARS_TRUSTED_JWKS` JSON array of trusted external IdP providers (issuer/audience/JWKS)
- `OARS_JWKS_AUTO_REFRESH_ENABLED` enable background JWKS refresh scheduler (`true`/`false`)
- `OARS_JWKS_AUTO_REFRESH_INTERVAL_SECONDS` scheduler interval in seconds (minimum `30`)
- `OARS_APPROVAL_STEP_UP_SECRET` shared step-up code required for critical approval decisions (default `stepup_dev_code`)
- `OARS_IMMUTABLE_LEDGER_PATH` append-only immutable ledger file path for receipts and security events
- `OARS_VAULT_KEY` encryption secret for connector vault entries (default is development-only value)
- `OARS_DASHBOARD_ENABLED` enable `/dashboard` in production (`true`/`false`; default `false` in production)
- `OARS_DATA_ENCRYPTION_KEY` encryption key for sensitive persisted payload fields
- `OARS_DATA_ENCRYPTION_ENABLED` enable/disable field-level at-rest encryption (`true`/`false`)
  - `OARS_STORE` persistence backend selector (`file` or `postgres`)
  - `OARS_POSTGRES_URL` Postgres connection string used when `OARS_STORE=postgres`
  - `OARS_BACKPLANE_MODE` execution mode (`inline` or `queue`)
  - `OARS_BACKPLANE_DRIVER` backplane driver (`postgres` or `file`)
  - `OARS_BACKPLANE_LOCK_TIMEOUT_SECONDS` reclaim running jobs after this timeout
  - `OARS_BACKPLANE_MAX_ATTEMPTS` max attempts before dead-letter
  - `OARS_BACKPLANE_RETRY_DELAY_SECONDS` delay before retrying a failed job
  - `OARS_MCP_UPSTREAMS` JSON array of MCP upstream servers (`id`, `url`, optional `headers`)
  - `OARS_MCP_ALLOW_PRIVATE_NETWORK` allow private-network upstream URLs (`true`/`false`)
  - `OARS_MCP_TOOL_CACHE_TTL_SECONDS` tool list cache TTL for MCP proxy
  - `OARS_MCP_ALLOWED_ORIGINS` optional Origin allowlist for `/mcp` requests (comma-separated; supports `*`)
  - `OARS_BACKUP_ROOT_PATH` backup artifact root directory
  - `OARS_DR_DRILL_REPORTS_PATH` disaster recovery drill report directory
  - `OARS_DR_DRILL_WORKSPACE_PATH` temporary drill workspace directory
- `OARS_MTLS_ENABLED` enforce workload mTLS identity checks for service-role tokens (`true`/`false`)
- `OARS_MTLS_MODE` workload identity mode (`header` or `tls`)
- `OARS_MTLS_TRUSTED_IDENTITIES_FILE` path to JSON file containing trusted identities (same schema as `OARS_MTLS_TRUSTED_IDENTITIES`)
- `OARS_MTLS_TRUSTED_IDENTITIES` JSON array of trusted workload identities (`subject`, `fingerprintSha256`, optional `serviceAccountId`, `tenantIds`)
- `OARS_MTLS_ATTESTATION_SECRET` optional HMAC secret for forwarded mTLS attestation headers
- `OARS_MTLS_MAX_CLOCK_SKEW_SECONDS` max allowed timestamp skew for mTLS attestation validation
- `OARS_TLS_CERT_PATH` TLS server certificate (PEM)
- `OARS_TLS_KEY_PATH` TLS server private key (PEM)
- `OARS_MTLS_CA_PATH` CA bundle for validating client certs (PEM)

Security hardening: when `NODE_ENV=production`, OARS requires `OARS_JWT_SECRET`, `OARS_VAULT_KEY`, and
`OARS_APPROVAL_STEP_UP_SECRET` to be set to non-development values. To bypass this check (not recommended), set
`OARS_ALLOW_INSECURE_DEFAULTS=1`.

## How It Works (High Level)

1. A client (agent SDK, MCP client, or any service) submits an action request.
2. OARS authenticates the caller (static token or JWT) and resolves tenant context.
3. OARS evaluates policy + risk and optionally routes through an approval workflow.
4. If approved, OARS executes via a connector (or queues execution when backplane is enabled).
5. OARS emits signed, tamper-evident receipts and security events for auditing and compliance evidence.

Integration options:

- **REST API**: call `/v1/*` endpoints directly.
- **TypeScript SDK**: import the `./sdk` subpath export described in `docs/03-architecture/sdk.md`.
- **MCP Proxy**: connect to `/mcp` to use upstream MCP tools with OARS policy/receipt controls (`docs/03-architecture/mcp-proxy.md`).

## API Reference

- Full API spec: `docs/03-architecture/api-specification.md`
- Source of truth (implemented routes): `src/api/routes/`

Key entrypoints:

- `GET /health`
- `POST /v1/actions` and `GET /v1/actions/:actionId`
- `POST /v1/receipts/verify`
- `POST/GET /mcp` (MCP Streamable HTTP)

## Quickstart (Demo)

Start the API:

```bash
npm ci
npm run dev
```

Confirm it’s up:

```bash
curl http://localhost:8080/health
```

Call an authenticated endpoint (dev token):

```bash
curl http://localhost:8080/v1/connectors -H "Authorization: Bearer dev_admin_token"
```

Submit an action (returns `actionId`):

```bash
curl -X POST http://localhost:8080/v1/actions \
  -H "Authorization: Bearer dev_admin_token" \
  -H "Content-Type: application/json" \
  -d '{"tenantId":"tenant_alpha","agentId":"demo_agent","userContext":{"userId":"demo_user"},"resource":{"toolId":"jira","operation":"create_ticket","target":"project:SEC"},"input":{"title":"Test ticket","description":"Hello from OARS demo"}}'
```

Fetch the action + receipts:

```bash
curl http://localhost:8080/v1/actions/<actionId> -H "Authorization: Bearer dev_admin_token"
```

Verify a receipt signature:

```bash
curl -X POST http://localhost:8080/v1/receipts/verify \
  -H "Authorization: Bearer dev_admin_token" \
  -H "Content-Type: application/json" \
  -d '{"receiptId":"<receiptId>"}'
```

## License

Apache-2.0 (see `LICENSE`).
