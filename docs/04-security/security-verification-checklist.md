# Security Verification Checklist

This checklist is intended to be run before any production deployment.

## Build And Dependency Gates

- `npm run typecheck`
- `npm test`
- `npm run conformance`
- `npm run release:gate`
- `npm audit --audit-level=high`

## Configuration Hardening

- Set a strong `OARS_JWT_SECRET` (do not use development defaults).
- Rotate `OARS_VAULT_KEY` and ensure it is stored in a secret manager.
- If `OARS_DATA_ENCRYPTION_ENABLED=true`, set `OARS_DATA_ENCRYPTION_KEY` and verify fail-closed behavior for missing keys.
- Set `OARS_ALLOWED_TOOLS` to an explicit allowlist.
- Ensure `OARS_API_TOKENS` is not configured with static shared dev tokens in production.

## Transport And Identity

- If using service-role tokens, enable workload identity enforcement (`OARS_MTLS_ENABLED=true`) and deploy behind an ingress/proxy that:
  - terminates mTLS
  - strips any inbound `x-oars-mtls-*` headers from untrusted clients
  - adds trusted workload identity headers only after successful mTLS verification
- Prefer real service-to-service mTLS enforcement at the network layer (service mesh / ingress mTLS) rather than relying only on forwarded headers.

## Tenant Isolation

- Validate that:
  - tenant-scoped reads/writes enforce tenant membership
  - cross-tenant reads return `403` or `404` (no leakage)
- Review admin-only endpoints for role enforcement.

## Receipt Integrity

- Verify:
  - signature validation on `POST /v1/receipts/verify`
  - key rotation continuity using `GET /v1/trust/tenants/:tenantId/keys`
  - immutable ledger verification (if enabled) via `GET /v1/admin/ledger/verify`

