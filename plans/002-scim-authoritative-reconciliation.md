# Plan 002: Make SCIM reconciliation revoke stale access

> **Executor instructions**: Follow every step and verification gate. Stop on any STOP condition; do not broaden scope. The reviewer maintains the plan index.
>
> **Drift check (run first)**: `git diff --stat fab1f43117058e81a3f02132807ecbe90801948e..HEAD -- src/core/services/scim-service.ts tests/api.test.ts docs/06-delivery/implementation-status.md`

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `fab1f43`, 2026-07-22

## Why this matters

SCIM sync is treated as enterprise identity reconciliation, but the current implementation only grants or updates memberships. If an active SCIM user is removed from all mapped groups, a previously granted OARS role remains indefinitely unless an administrator calls the separate deprovision endpoint. This plan makes the configured SCIM user set authoritative for SCIM-known subjects while preserving owners and unrelated manually managed subjects.

## Current state

- `src/core/services/scim-service.ts:233-270` resolves active group memberships and only calls `upsertMember`.
- `src/core/services/scim-service.ts:272-286` reports assigned/inactive/unmapped counts but no removals.
- `src/core/services/tenant-admin-service.ts:105-122` provides `listMembers` and audited `removeMember` methods.
- Existing core excerpt:

```ts
for (const [subject, role] of resolvedBySubject.entries()) {
  await this.tenantAdminService.upsertMember(tenantId, subject, role, actor);
}
```

- `tests/api.test.ts:2711-2863` is the existing end-to-end SCIM sync/deprovision test.
- `docs/06-delivery/implementation-status.md:156-164` explicitly lists authoritative precedence and conflict resolution as remaining production scope.

## Commands you will need

| Purpose | Command | Expected on success |
| --- | --- | --- |
| Target test | `npm test -- tests/api.test.ts -t "syncs scim"` | exit 0 |
| Typecheck | `npm run typecheck` | exit 0 |
| Full gate | `npm run check` | exit 0 |

## Scope

**In scope**:
- `src/core/services/scim-service.ts`
- `tests/api.test.ts`
- `docs/06-delivery/implementation-status.md`

**Out of scope**:
- Database schema changes or a new membership-source field.
- Removing tenant owners.
- Removing subjects that do not correspond to a known SCIM user.
- Changing role-priority semantics (`admin > operator > auditor`).

## Git workflow

- Branch: `advisor/002-scim-authoritative-reconciliation`
- Commit: `fix: revoke stale SCIM memberships`
- Do not push or open a PR.

## Steps

### Step 1: Define the safe authoritative boundary

During `syncTenantMembers`, build a set of all SCIM-known `userName` values and list current tenant members. After computing `resolvedBySubject`, identify members whose subject is SCIM-known but no longer resolves from an active user in a mapped group. Exclude role `owner` unconditionally and leave non-SCIM subjects untouched.

**Verify**: `npm run typecheck` → exit 0.

### Step 2: Revoke stale SCIM-known memberships with audit events

After upserts, call `tenantAdminService.removeMember` for each stale eligible subject. Use deterministic subject ordering to keep event/test behavior stable. Extend `SyncResult` and `scim.sync.completed` payload with `removedCount`; do not rename existing fields.

**Verify**: `npm run typecheck` → exit 0.

### Step 3: Extend the end-to-end SCIM test

Extend the test at `tests/api.test.ts:2711` so a user is first granted through a mapped group, then removed from that group's membership and synced again. Assert the user disappears from tenant members and `removedCount` is 1. Also create/assert an unrelated manual member survives, and ensure an owner cannot be removed even if a SCIM username collides.

**Verify**: `npm test -- tests/api.test.ts -t "syncs scim"` → pass.

### Step 4: Update production-scope documentation

Record authoritative membership reconciliation as implemented, including the boundary: only subjects represented by SCIM users are revoked automatically; owners and unrelated manual members are preserved.

**Verify**: `npm run check` → exit 0.

## Test plan

- Existing mapped active user remains assigned.
- Inactive user remains unassigned.
- Previously assigned SCIM-known user removed from all mapped groups is revoked.
- Manual non-SCIM member survives.
- Owner survives.
- Completion event/result includes `removedCount`.

## Done criteria

- [ ] Reconciliation revokes stale access only inside the defined SCIM boundary.
- [ ] Existing response fields remain compatible and `removedCount` is additive.
- [ ] Target and full test gates pass.
- [ ] Only in-scope files change.

## STOP conditions

- Tenant membership records no longer expose role/subject.
- Correct ownership boundaries require a persistent source-of-membership schema change.
- A test reveals existing intended behavior that manual assignments for SCIM-known subjects must always win; report the conflict instead of guessing.
- Verification fails twice.

## Maintenance notes

The subject-based boundary is deliberately conservative. If membership provenance is added later, migrate reconciliation to an explicit `source: scim` marker and backfill safely before widening revocation.
