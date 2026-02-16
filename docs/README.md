# Documentation Structure

This documentation is structured to drive full implementation, deployment, and adoption of OARS.

## Sections

- `01-strategy`: market need, positioning, and system vision
- `02-product`: product requirements, use cases, acceptance criteria
- `03-architecture`: architecture, APIs, data model, interoperability
- `04-security`: security design, controls, and threat model
- `05-compliance`: control mappings and evidence operations
- `06-delivery`: build sequencing, staffing model, and testing
- `07-operations`: deployment, reliability, and incident operations
- `08-adoption`: rollout, pilot strategy, and standardization path
- `09-governance`: decision process, risk ownership, and risk register
- `templates`: reusable templates for design/operations artifacts

## Detailed File List

- `01-strategy/vision.md`
- `02-product/product-requirements.md`
- `02-product/use-cases.md`
- `03-architecture/system-architecture.md`
- `03-architecture/receipt-specification.md`
- `03-architecture/api-specification.md`
- `03-architecture/integration-patterns.md`
- `03-architecture/sdk.md`
- `04-security/security-architecture.md`
- `04-security/threat-model.md`
- `04-security/security-verification-checklist.md`
- `05-compliance/compliance-mapping.md`
- `05-compliance/evidence-operations.md`
- `06-delivery/full-build-plan.md`
- `06-delivery/work-breakdown.md`
- `06-delivery/testing-strategy.md`
- `06-delivery/implementation-status.md`
- `06-delivery/full-depth-review.md`
- `06-delivery/productionization-master-checklist.md`
- `07-operations/operations-manual.md`
- `07-operations/runbooks.md`
- `07-operations/runbooks/backup-restore-validation.md`
- `07-operations/dr-drill-evidence-log.md`
- `07-operations/container-deployment.md`
- `07-operations/enterprise-deployment-checklist.md`
- `08-adoption/standardization-playbook.md`
- `08-adoption/pilot-program.md`
- `08-adoption/pilot-evidence.md`
- `09-governance/governance-model.md`
- `09-governance/decision-log.md`
- `09-governance/risk-register.md`
- `templates/adr-template.md`
- `templates/runbook-template.md`
- `templates/policy-template.md`

## How To Use This Repo

1. Read `01-strategy` and `02-product` to lock target scope.
2. Implement from `03-architecture` and `04-security` in parallel.
3. Set up assurance from `05-compliance` and `06-delivery`.
4. Prepare launch from `07-operations` and `08-adoption`.
5. Operate with ongoing risk governance from `09-governance`.

## Definition Of Done For Platform v1

- All product modules in `docs/02-product/product-requirements.md` are implemented.
- Security controls listed in `docs/04-security/security-architecture.md` are enforced.
- Compliance evidence packs are auto-generated as described in `docs/05-compliance/evidence-operations.md`.
- SLOs in `docs/07-operations/operations-manual.md` are measured and reported.
- Pilot and adoption path in `docs/08-adoption/standardization-playbook.md` is active.
