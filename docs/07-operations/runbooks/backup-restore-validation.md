# Runbook: Backup Restore Validation

## Purpose

Validate backup integrity, restore readiness, and disaster recovery drill evidence for OARS control-plane artifacts.

## Triggers

- Quarterly disaster recovery drill schedule.
- Any incident suggesting state corruption, ledger integrity risk, or recovery readiness gap.

## Preconditions

- Admin operator with access to backup APIs and scripts.
- Current production snapshot and immutable evidence retention policy reviewed.
- Maintenance window approved for restore rehearsal.

## Steps

1. Create a checkpoint backup.
- API: `POST /v1/admin/backups`
- Script: `npm run backup:create -- --reason="quarterly_drill"`
- Expected output: backup manifest with `backupId`, file checksums, and missing-required file report.

2. Validate backup catalog and storage status.
- API: `GET /v1/admin/backups?limit=10`
- API: `GET /v1/admin/backups/status`
- Expected output: latest backup visible, managed file inventory populated, backup count incremented.

3. Execute DR drill and capture evidence.
- API: `POST /v1/admin/backups/drills`
- Script: `npm run backup:drill -- --reason="quarterly_drill"`
- Expected output: drill report with `status: passed`, checksum validation checks, ledger integrity check, and report path.

4. If performing a restore rehearsal, restore from selected backup.
- API: `POST /v1/admin/backups/restore`
- Script: `npm run backup:restore -- --backupId=<id> --reason="restore_rehearsal"`
- Expected output: restored file list and `restartRequired: true`.
- Important: restart control-plane services before resuming writes after restore.

## Verification

- Drill report is persisted in drill report storage (`data/dr-drill-reports` by default).
- `GET /v1/admin/backups/drills?limit=10` returns the latest report.
- Immutable ledger verification remains valid after service restart (`GET /v1/admin/ledger/verify`).

## Escalation

- Owner team: SRE + platform engineering.
- Escalate to platform security if ledger integrity or key artifact validation fails.
- Treat drill failure as `SEV2` until corrective action owner and ETA are assigned.

## Post-Incident Actions

- Open corrective action tickets for each failed drill check.
- Update this runbook and related automation scripts within 5 business days.
- Attach drill report JSON and remediation evidence to quarterly resilience review.
