# Container Deployment (Docker)

This repo includes a `Dockerfile` and `docker-compose.yml` suitable for local containerized execution and as a baseline for production hardening.

## Run

```bash
docker compose up --build
```

## Run With Postgres Store

```bash
docker compose -f docker-compose.postgres.yml up --build
```

Notes:

- This switches persistence for core state to Postgres via `OARS_STORE=postgres`.
- The immutable ledger, signing keys, vault secrets, and SIEM retry queue remain file-backed under `./data` by default (mounted into `/app/data`).

## Run With Backplane Worker (Queue Mode)

```bash
docker compose -f docker-compose.backplane.yml up --build
```

Notes:

- Sets `OARS_BACKPLANE_MODE=queue` so the API enqueues execution jobs.
- Runs a separate `worker` service (`node dist/worker/index.js`) that claims jobs and executes actions.

## Run With mTLS (TLS Client Certificates)

Generate certificates:

```bash
docker compose -f docker-compose.mtls.yml run --rm certgen
```

Run:

```bash
docker compose -f docker-compose.mtls.yml up --build
```

API base URL:

- `http://localhost:8080`

Persisted state:

- The default file-backed state is stored under `./data` (mounted into `/app/data`).

## Production Notes

- Do not use dev tokens or default secrets in production.
- Provide secure values for:
  - `OARS_JWT_SECRET`
  - `OARS_DATA_ENCRYPTION_KEY`
  - `OARS_VAULT_KEY`
- For enterprise deployments, plan to replace file-backed persistence with production stores (see `docs/06-delivery/productionization-master-checklist.md`).
  - For Postgres mode, use your standard Postgres backup strategy (`pg_dump`/WAL shipping) for the `oars_*` tables.
