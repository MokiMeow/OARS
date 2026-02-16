# Runbook Catalog

## Purpose

Define required operational runbooks for production readiness.

## Required Runbooks

1. API outage response
- Trigger: API error rate exceeds threshold for 5 minutes.
- Owner: Platform on-call.

2. Policy engine degradation
- Trigger: p95 decision latency above SLO.
- Owner: Core backend team.

3. Receipt signing failure
- Trigger: signature generation or verification failures.
- Owner: Security engineering.

4. Connector incident response
- Trigger: connector retries spike or unexpected action failures.
- Owner: Integrations team.

5. Cross-tenant access alert
- Trigger: authorization anomaly or tenant boundary violation signal.
- Owner: Security operations.

6. Evidence export failure
- Trigger: scheduled compliance export failure.
- Owner: GRC operations.

7. Key rotation emergency
- Trigger: suspected key compromise or urgent rotation directive.
- Owner: Platform security.

8. Regional failover
- Trigger: regional outage or control-plane instability.
- Owner: SRE.

9. Backup restore validation
- Trigger: quarterly drill schedule or integrity concern.
- Owner: SRE and platform engineering.
- Implemented runbook: `docs/07-operations/runbooks/backup-restore-validation.md`
- Drill evidence log: `docs/07-operations/dr-drill-evidence-log.md`

10. Incident communications
- Trigger: SEV1/SEV2 incident declaration.
- Owner: Incident commander.

## Runbook Format

All runbooks must use `docs/templates/runbook-template.md`.

## Validation Cadence

- Monthly tabletop reviews for top 5 runbooks.
- Quarterly live drills for key rotation and regional failover.
- Post-incident runbook updates within 5 business days.
