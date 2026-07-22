# Plan 001: Correct SDK retry classification and server-directed backoff

> **Executor instructions**: Follow this plan step by step. Run every verification command and confirm the expected result before moving on. If a STOP condition occurs, stop and report; do not improvise. The reviewer maintains `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat fab1f43117058e81a3f02132807ecbe90801948e..HEAD -- src/sdk/client.ts tests/sdk.test.ts docs/03-architecture/sdk.md`
> If an in-scope file changed, compare the excerpts below with live code. A behavioral mismatch is a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `fab1f43`, 2026-07-22

## Why this matters

The SDK correctly recognizes retryable HTTP statuses at first, but then throws an `OarsHttpError` inside the same `try` block and its catch handler retries every error. Safe GET calls therefore retry 400/401/403/404 responses, increasing latency and load without any chance of success. The repair must retain retry behavior for transport failures and 408/425/429/5xx responses while honoring `Retry-After` when the server supplies it.

## Current state

- `src/sdk/client.ts:36-38` defines the intended retryable status set.
- `src/sdk/client.ts:137-155` retries retryable responses, then constructs `OarsHttpError` for all other responses.
- `src/sdk/client.ts:156-161` currently retries any caught error:

```ts
} catch (error) {
  lastError = error;
  const retryable = options?.retryMode === "safe" && attempt < maxAttempts;
  if (retryable) {
    await sleep(200 * 2 ** (attempt - 1));
    continue;
  }
  throw error;
}
```

- `tests/sdk.test.ts:96-167` is the existing SDK integration-test pattern and uses an injected fetch adapter.
- `docs/03-architecture/sdk.md` promises that safe requests retry; preserve that vocabulary and clarify which failures qualify.

## Commands you will need

| Purpose | Command | Expected on success |
| --- | --- | --- |
| Target tests | `npm test -- tests/sdk.test.ts` | exit 0; all SDK tests pass |
| Typecheck | `npm run typecheck` | exit 0, no errors |
| Full gate | `npm run check` | exit 0; tests and build pass |

## Scope

**In scope**:
- `src/sdk/client.ts`
- `tests/sdk.test.ts`
- `docs/03-architecture/sdk.md`

**Out of scope**:
- Server retry behavior or SIEM queues.
- Changing default `maxRetries` or the public response types.
- Retrying non-idempotent action submissions without an idempotency key.

## Git workflow

- Branch: `advisor/001-sdk-retry-correctness`
- Use conventional commit style, e.g. `fix: correct SDK retry classification`.
- Do not push or open a PR; the reviewer will inspect and publish.

## Steps

### Step 1: Separate response failures from transport failures

Refactor `requestJson` so non-retryable HTTP responses are thrown once and are never retried by the catch block. An `OarsHttpError` must only be retried when its status is in `shouldRetry`; because retryable responses are already handled before construction, the simplest safe catch rule is to retry only errors that are not `OarsHttpError`. Preserve timeout aborts and network exceptions as retryable for `retryMode: "safe"`.

**Verify**: `npm run typecheck` → exit 0.

### Step 2: Honor bounded Retry-After guidance

For retryable HTTP responses, read `Retry-After` as either delta-seconds or an HTTP date. Use it when valid, otherwise retain exponential backoff. Cap server-directed delay at 30 seconds and never accept negative delay. Keep the delay helper deterministic and unit-testable; do not add a runtime dependency.

**Verify**: `npm run typecheck` → exit 0.

### Step 3: Add regression tests and document the contract

In `tests/sdk.test.ts`, add focused injected-fetch cases for: a 404 called exactly once even with retries enabled; a transient 503 followed by success; a thrown network error followed by success; and malformed/valid `Retry-After` parsing without real-time sleeps (use Vitest fake timers or a small injected sleep function). Update the SDK document with the retryable statuses, transport-failure rule, and 30-second cap.

**Verify**: `npm test -- tests/sdk.test.ts` → all tests pass.

## Test plan

- Model the client construction after `tests/sdk.test.ts:96-105`.
- Assert fetch call counts, not merely final results.
- Assert 401/404 errors preserve status/code/request ID and are not retried.
- Assert submission without an idempotency key remains single-attempt.
- Verification: `npm run check` → exit 0.

## Done criteria

- [ ] Non-retryable HTTP errors produce exactly one request.
- [ ] Safe transport failures and configured retryable statuses retry up to `maxRetries`.
- [ ] Valid `Retry-After` is honored with a 30-second cap; invalid values fall back safely.
- [ ] `npm run check` exits 0.
- [ ] No files outside the in-scope list are modified.

## STOP conditions

- `OarsHttpError` no longer exposes numeric `status`.
- The fix would require changing server response shapes.
- A verification command fails twice after a focused correction.
- An in-scope excerpt has behaviorally drifted.

## Maintenance notes

Reviewers should scrutinize double-retry paths and ensure abort/network errors are distinguishable from HTTP errors. Future retry policies should remain explicit per operation; do not make unsafe POSTs retryable by default.
