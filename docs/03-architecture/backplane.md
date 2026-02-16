# Event-Driven Backplane (PC-008)

OARS supports an event-driven execution backplane for decoupling API request latency from connector execution.

When `OARS_BACKPLANE_MODE=queue`:

- `POST /v1/actions` records the action + receipts and **enqueues** an execution job instead of executing inline.
- A separate worker process claims jobs from the backplane and executes approved actions.
- This enables horizontal scaling and isolates connector execution from the API tier.

## Modes

- `OARS_BACKPLANE_MODE=inline` (default): execute actions inline in the API process.
- `OARS_BACKPLANE_MODE=queue`: enqueue jobs and rely on a worker (`node dist/worker/index.js`).

## Backplane Drivers

- `OARS_BACKPLANE_DRIVER=postgres` (recommended): durable queue stored in Postgres (`oars_execution_jobs`).
- `OARS_BACKPLANE_DRIVER=file`: local JSON queue file (development only).

## Operational Notes

- The backplane provides *at-least-once* processing under worker crashes. Connectors should be idempotent where possible.
- Retry behavior is controlled via `OARS_BACKPLANE_MAX_ATTEMPTS` and `OARS_BACKPLANE_RETRY_DELAY_SECONDS`.

## Reference Docker Topology

Use `docker-compose.backplane.yml` to run:

- `oars` API tier
- `worker` execution tier
- `postgres` durable storage + job queue

