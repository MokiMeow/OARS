# Evidence Operations

## Purpose

Define how OARS continuously produces high-quality, audit-ready evidence.

## Evidence Pipeline

1. Ingest signed receipts and policy lifecycle events.
2. Normalize artifacts into evidence graph records.
3. Map graph records to framework controls.
4. Validate control coverage and identify gaps.
5. Generate signed evidence bundles.

## Evidence Graph Entities

- `Action`
- `Receipt`
- `PolicyVersion`
- `ApprovalDecision`
- `Actor`
- `ControlMapping`
- `EvidenceBundle`

## Bundle Types

- Periodic audit bundle (`monthly`, `quarterly`)
- Incident-specific evidence bundle
- Tenant on-demand export bundle

## Bundle Metadata

- bundle ID and timestamp
- tenant and scope
- framework and control list
- source artifact hash list
- bundle signature and verification payload

## Evidence Quality Gates

- Signature validity check
- Receipt chain continuity check
- Control coverage threshold check
- Duplicate and stale artifact detection

## Operational Cadence

- Daily: evidence completeness scan
- Weekly: control drift report
- Monthly: signed baseline export
- Quarterly: audit rehearsal drill

## Roles And Responsibilities

- GRC team: owns control mapping and reporting requirements
- Platform team: owns pipeline reliability and exports
- Security team: validates integrity and incident evidence quality

## Key Metrics

- control coverage percentage
- evidence generation lead time
- failed verification count
- manual evidence requests per audit cycle

