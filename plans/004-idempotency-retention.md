# Plan 004: Activate bounded idempotency-record retention

> **Executor instructions**: Follow each step and gate. Stop instead of broadening scope. The reviewer maintains the plan index.
>
> **Drift check (run first)**: `git diff --stat fab1f43117058e81a3f02132807ecbe90801948e..HEAD -- src/core/services/idempotency-retention-service.ts src/api/server.ts tests/idempotency-retention.test.ts .env.example README.md docs/06-delivery/implementation-status.md`

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: reliability
- **Planned at**: commit `fab1f43`, 2026-07-22

## Why this matters

Both file and Postgres stores implement `pruneIdempotencyRecords`, but no runtime code invokes it. Every unique action idempotency key therefore remains forever, causing unbounded state-file and table/index growth. A lifecycle-managed retention task will bound storage while keeping the deduplication window explicit and configurable.

## Current state

- `src/core/store/platform-store.ts:819-833` prunes file-backed records and persists only when rows were removed.
- `src/core/store/postgres-platform-store.ts:1212-1220` performs the equivalent indexed SQL delete.
- `src/api/server.ts:188-208` shows the repository convention for an unref'd maintenance timer and cleanup in `onClose`.
- No caller exists: `rg -n "pruneIdempotencyRecords" src` currently returns only the interface and two store implementations.
- Existing idempotency API coverage is in `tests/api.test.ts:253-338`.

## Commands you will need

| Purpose | Command | Expected on success |
| --- | --- | --- |
| Target tests | `npm test -- tests/idempotency-retention.test.ts` | exit 0 |
| Typecheck | `npm run typecheck` | exit 0 |
| Full gate | `npm run check` | exit 0 |

## Scope

**In scope**:
- `src/core/services/idempotency-retention-service.ts` (new)
- `src/api/server.ts`
- `tests/idempotency-retention.test.ts` (new)
- `.env.example`
- `README.md`
- `docs/06-delivery/implementation-status.md`

**Out of scope**:
- Changing idempotency key semantics or response replay behavior.
- Adding a new storage table or migration.
- Pruning actions, receipts, or audit evidence.
- Distributed scheduler leadership; store deletes must remain safe if multiple replicas run them.

## Git workflow

- Branch: `advisor/004-idempotency-retention`
- Commit: `feat: schedule idempotency record retention`
- Do not push or open a PR.

## Steps

### Step 1: Add a small retention service

Create `IdempotencyRetentionService` around `PlatformStore.pruneIdempotencyRecords`. Accept injected clock and timer/sleep seams needed by tests. Expose `runOnce`, `start`, `stop`, and a status snapshot containing running, lastRunAt, lastPrunedCount, totalPrunedCount, and lastError. Defaults: 24-hour TTL and 1-hour interval; validate TTL >= 60 seconds and interval >= 30 seconds. Ensure `start` is idempotent and timers are unref'd when supported.

**Verify**: `npm run typecheck` → exit 0.

### Step 2: Wire startup and shutdown lifecycle

In `buildServer`, construct the service from `OARS_IDEMPOTENCY_TTL_SECONDS` and `OARS_IDEMPOTENCY_PRUNE_INTERVAL_SECONDS`, run one best-effort prune at startup, start the interval, and stop it in `onClose`. Background errors must be captured in status and must not crash the API or leak secrets.

**Verify**: `npm run typecheck` → exit 0.

### Step 3: Test both behavior and lifecycle

Add unit tests using a fake `PlatformStore` or a narrowly typed stub. Cover cutoff calculation, total/status counters, invalid configuration fallback, start idempotence, no overlapping runs, error capture, and stop preventing later executions. Also assert server close stops the timer without open-handle warnings.

**Verify**: target tests → pass with no open-handle warning.

### Step 4: Document the deduplication window

Add the two environment variables to `.env.example` and runtime-config README. Explain that replay guarantees apply within the configured TTL and that audit/action/receipt retention is unaffected. Record completion in implementation status.

**Verify**: `npm run check` → exit 0.

## Test plan

- Cutoff ISO equals injected now minus TTL.
- Successful runs update last/total counts.
- Repeated `start` creates one timer only.
- Concurrent tick while running is skipped.
- Store rejection is recorded and later runs can recover.
- `stop` and server close leave no active timer.

## Done criteria

- [ ] A startup prune and recurring bounded prune are active.
- [ ] File and Postgres implementations require no schema change.
- [ ] Failures do not crash the API and are observable through service status/tests.
- [ ] TTL semantics are documented.
- [ ] Full gate passes and only in-scope files change.

## STOP conditions

- The store interface no longer has `pruneIdempotencyRecords`.
- A correct implementation would prune audit evidence or action records.
- Tests require real multi-second waits.
- A background error becomes an unhandled rejection.
- Verification fails twice.

## Maintenance notes

Multiple replicas may run the same prune safely because both implementations delete/filter by cutoff. If a future backend makes pruning non-idempotent, introduce leader election before reusing this scheduler.
