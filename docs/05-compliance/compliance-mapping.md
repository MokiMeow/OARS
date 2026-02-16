# Compliance Mapping

## Objective

Translate platform controls and runtime artifacts into reusable compliance evidence.

## Supported Frameworks (v1)

- EU AI Act aligned controls
- ISO/IEC 42001 controls
- SOC2-aligned trust service criteria mapping

## Control Families

1. Governance
- Policy ownership
- Change management
- Accountability records

2. Risk Management
- Risk tiering for actions
- Approval requirements by impact
- Exception handling workflow

3. Access And Identity
- Access reviews
- Least privilege
- Delegated identity traceability

4. Security And Integrity
- Cryptographic integrity controls
- Tamper evidence
- Incident logging and forensic readiness

5. Operational Resilience
- Monitoring and alerting
- Incident response
- Backup and recovery controls

## Artifact To Control Mapping

- Policy publication logs -> governance/change controls
- Signed action receipts -> integrity and accountability controls
- Approval records -> high-risk decision controls
- Access logs -> identity/access controls
- Incident records -> operational resilience controls

## Control Mapping Format

Each control mapping entry includes:

- `framework`
- `control_id`
- `control_description`
- `oars_artifact_types`
- `collection_method`
- `verification_method`

## Receipt Queryability (Control Tags)

Control mappings may optionally define `receiptFilters` to make evidence retrieval queryable by control tag.

Operationally:

1. Admin upserts a control mapping with `receiptFilters` (example: receipts from `jira` `create_ticket` operations).
2. Auditors/operators query receipts with `GET /v1/receipts?tenantId=<id>&framework=<framework>&controlId=<controlId>` to retrieve receipts scoped to the control mapping filters.

This enables repeatable evidence collection workflows without embedding control identifiers directly into every receipt.

## Required Outputs

- control coverage dashboard
- missing evidence detector
- signed evidence package generation

## Operating Model

1. Define control catalog per framework.
2. Bind receipt and operational artifact types to controls.
3. Validate evidence completeness on schedule.
4. Export signed evidence bundles for audit cycles.

## Acceptance Criteria

- Evidence can be reproduced from raw signed artifacts.
- Control mapping changes are version-controlled.
- Auditors can independently verify evidence package integrity.
