# Plan 003: Bound OIDC and JWKS network operations

> **Executor instructions**: Execute each step and verification exactly. Stop and report on a STOP condition. The reviewer maintains the index.
>
> **Drift check (run first)**: `git diff --stat fab1f43117058e81a3f02132807ecbe90801948e..HEAD -- src/core/services/jwks-service.ts tests/api.test.ts .env.example docs/06-delivery/implementation-status.md`

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `fab1f43`, 2026-07-22

## Why this matters

OIDC discovery and JWKS refresh currently await an injected one-argument fetch indefinitely. A slow or unavailable identity provider can therefore stall manual refreshes, scheduler cycles, and token verification refresh paths. The service already preserves the last good key set on failures; this plan adds bounded requests and controlled retry/backoff without clearing trusted cached keys.

## Current state

- `src/core/services/jwks-service.ts:18-23` defines a minimal fetch type with no signal/options.
- `src/core/services/jwks-service.ts:214-230` calls discovery fetch directly.
- `src/core/services/jwks-service.ts:260-295` calls JWKS fetch directly and replaces keys only after a valid body.
- `src/core/services/jwks-service.ts:318-348` runs serial scheduler cycles and prevents overlap.
- `tests/api.test.ts:2544-2704` covers discovery, refresh, authentication, and scheduler start/stop using an injected fetch.
- `docs/06-delivery/implementation-status.md` lists OIDC resilience hardening as the first remaining production item.

## Commands you will need

| Purpose | Command | Expected on success |
| --- | --- | --- |
| Target tests | `npm test -- tests/api.test.ts -t "jwks|OIDC|refresh scheduler"` | exit 0 |
| Typecheck | `npm run typecheck` | exit 0 |
| Full gate | `npm run check` | exit 0 |

## Scope

**In scope**:
- `src/core/services/jwks-service.ts`
- `tests/api.test.ts`
- `.env.example`
- `docs/06-delivery/implementation-status.md`

**Out of scope**:
- JWT algorithms, issuer/audience validation, or trust-provider schema.
- Persisting JWKS across process restarts.
- Adding a third-party retry library.
- Removing a previously valid key set solely because refresh failed.

## Git workflow

- Branch: `advisor/003-jwks-network-resilience`
- Commit: `feat: bound OIDC and JWKS refresh requests`
- Do not push or open a PR.

## Steps

### Step 1: Add validated timeout/retry configuration

Extend `JwksServiceOptions` with optional `requestTimeoutMs`, `maxRefreshAttempts`, and an injectable sleep function for deterministic tests. Defaults: 5 seconds and 2 total attempts. Add environment parsing for `OARS_JWKS_REQUEST_TIMEOUT_MS` and `OARS_JWKS_MAX_REFRESH_ATTEMPTS`, with positive bounded values (timeout 100-30000 ms, attempts 1-5). Change `FetchLike` to accept `RequestInit` so an `AbortSignal` can be passed.

**Verify**: `npm run typecheck` → exit 0.

### Step 2: Centralize bounded fetch and retry behavior

Create a private helper used by both discovery and JWKS refresh. Each attempt gets a fresh `AbortController`; always clear its timer. Retry only timeout/network exceptions and retryable 408/425/429/5xx responses, using bounded exponential backoff. Do not retry validation failures in a successful JSON response. Keep failure messages non-secret and retain existing keys/state when all attempts fail.

**Verify**: `npm run typecheck` → exit 0.

### Step 3: Test timeout, recovery, and stale-key preservation

Extend the identity test area with injected fetch cases for: aborting a never-completing request; transient 503 then valid JWKS; invalid JSON/body with no retry; and refresh failure after an initial valid key set while `getSigningKey` still returns the prior key. Use fake timers or injected sleep—tests must not wait real seconds.

**Verify**: target test command → all matching tests pass.

### Step 4: Document operations knobs and completed resilience boundary

Add commented variables to `.env.example`. Update implementation status to state bounded timeout/retry and last-known-good key preservation; do not claim cross-process persistent caching.

**Verify**: `npm run check` → exit 0.

## Test plan

- Timeout aborts and records a provider error.
- Transient retryable response succeeds on the next bounded attempt.
- Non-retryable/invalid successful payload is not retried.
- Last-known-good keys remain usable after a failed refresh.
- Scheduler `inProgress` returns to false after failure.

## Done criteria

- [ ] No discovery/JWKS HTTP request can wait indefinitely.
- [ ] Retry count and timeout are bounded and validated.
- [ ] Cached valid keys survive refresh failures.
- [ ] Full gate passes; only in-scope files change.

## STOP conditions

- `fetchFn` compatibility cannot be preserved for existing tests/callers.
- Implementing the behavior requires weakening issuer, audience, algorithm, or SSRF checks.
- A failure clears trusted keys or causes overlapping scheduler runs.
- Verification fails twice.

## Maintenance notes

Review abort-timer cleanup and scheduler state carefully. Persistent JWKS caching and HTTP cache validators remain separate follow-ups because they require a storage/expiry policy.
