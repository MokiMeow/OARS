# Operations Manual

## Production SLOs

- API availability: `99.95%` monthly
- Policy decision p95 latency: `< 150ms`
- Receipt persistence success: `99.999%`
- Evidence export success: `99.9%`

## Deployment Model

- Multi-region active-active control plane
- Region-local data plane with tenant partitioning
- Managed queues for asynchronous operations

## Monitoring Baseline

- Golden signals: latency, traffic, errors, saturation
- Security signals: denied high-risk actions, auth failures, policy drift
- Data integrity signals: signature failures, chain gaps
- Workload identity signals: mTLS identity verification failures (`/v1/admin/security/mtls/status`)
- Ops dashboard endpoint: `/v1/admin/ops/dashboard?tenantId=<id>`
- Alert routing controls: `/v1/admin/ops/alert-routing`

## Alert Delivery Channels

Alert routing rules store channel IDs (for example `slack_secops`, `pagerduty`).

Channel delivery is configured via:

- `OARS_ALERT_CHANNELS`: JSON array of channel configs.
- Legacy fallback: `OARS_ALERT_WEBHOOK_URL` (treated as a `generic_webhook` channel named `legacy_alert_webhook`).

Supported channel types:

- `slack_webhook` (`{ id, type, url }`)
- `pagerduty_events_v2` (`{ id, type, routingKey, source? }`)
- `generic_webhook` (`{ id, type, url, headers? }`)

## On-Call Model

- 24x7 primary/secondary rotation
- Severity levels: `SEV1`, `SEV2`, `SEV3`
- Response targets:
  - `SEV1`: acknowledge in 5 minutes
  - `SEV2`: acknowledge in 15 minutes
  - `SEV3`: acknowledge in 60 minutes

## Incident Command

1. Declare severity and assign incident commander.
2. Stabilize customer impact.
3. Preserve forensic evidence.
4. Run communication cadence.
5. Close with RCA and corrective actions.

## Backup And Recovery

- Daily full backups with hourly incremental snapshots
- Cross-region backup replication
- Quarterly restore verification drills
- Automated backup scripts: `npm run backup:create`, `npm run backup:restore`, `npm run backup:drill`
- Backup APIs: `/v1/admin/backups`, `/v1/admin/backups/restore`, `/v1/admin/backups/drills`

RTO/RPO targets:

- RTO: `<= 60 minutes`
- RPO: `<= 15 minutes`

## Change Management

- Progressive rollouts with canary stages
- Automated rollback triggers on SLO degradation
- Maintenance windows for non-critical changes
- Release gate automation: `npm run release:gate`
- Rollback automation stub: `scripts/deploy/rollback.ps1`

## Operational Reviews

- Weekly SLO and incident review
- Monthly security operations review
- Quarterly resilience and disaster recovery review
