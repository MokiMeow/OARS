# API Specification

## API Conventions

- Base path: `/v1`
- Auth: OAuth2 bearer tokens (scoped)
- Content type: `application/json`
- Idempotency header: `Idempotency-Key`
- Correlation header: `X-Request-Id`
- Service workload identity headers (when mTLS enforcement enabled):
  - `X-OARS-mTLS-Subject`
  - `X-OARS-mTLS-Fingerprint`
  - `X-OARS-mTLS-Issued-At` + `X-OARS-mTLS-Signature` (if attestation secret required)
- Field naming:
  - Canonical API field naming is `camelCase`.
  - Compatibility: selected ingress payloads accept `snake_case` aliases for key fields (example: action submission).

## Endpoints

### Action Submission

`POST /v1/actions`

Purpose:

- Submit agent action for policy evaluation and possible execution.

Request:

```json
{
  "tenantId": "t_001",
  "agentId": "agent_finops_01",
  "userContext": {
    "userId": "u_123",
    "sessionId": "s_456"
  },
  "context": {
    "environment": "prod",
    "dataTypes": ["pii"]
  },
  "resource": {
    "toolId": "jira",
    "operation": "create_ticket",
    "target": "project:SEC"
  },
  "input": {
    "summary": "Suspicious outbound traffic",
    "priority": "high"
  }
}
```

Notes:

- Canonical fields are `camelCase`, but action submission accepts selected `snake_case` aliases (`tenant_id`, `agent_id`, `user_context.user_id`, `resource.tool_id`, etc.).
- `context.requestedAt` is accepted for compatibility and simulations, but action submission is anchored to platform time for policy evaluation.

Response:

```json
{
  "actionId": "act_abc123",
  "state": "approval_required",
  "receiptId": "rcpt_001",
  "approvalId": "appr_001",
  "stepUpRequired": false
}
```

### Action Status

`GET /v1/actions/{actionId}`

Returns current state, decision rationale, and related receipt IDs.

### Approval Decision

`POST /v1/approvals/{approvalId}/decision`

Request:

```json
{
  "decision": "approve",
  "reason": "Business urgency validated",
  "step_up_code": "string-when-required"
}
```

Notes:

- Approval workflows may include multiple stages.
- If additional stages remain after an `approve` decision, response remains in `approval_required` state until final stage completion.
- Stages may define SLA timers and escalation targets; overdue stages are escalated via admin scan endpoint.
- Critical-risk approvals require step-up authentication data in the decision payload.

### Receipt Retrieval

`GET /v1/receipts/{receiptId}`

Returns canonical signed receipt.

### Receipt Search

`GET /v1/receipts?tenantId=<id>&toolId=<id>&operation=<op>&actorUserId=<id>&actorAgentId=<id>&policyDecision=<d>&policyVersion=<v>&policyRuleId=<id>&framework=<soc2|iso_42001|eu_ai_act>&controlId=<id>&limit=<n>`

Returns tenant-scoped receipts with optional filters.

### Receipt Verification

`POST /v1/receipts/verify`

Request:

```json
{
  "receiptId": "optional-id",
  "receipt": {},
  "chain": [],
  "publicKeyPem": "optional",
  "publicKeys": [{ "keyId": "key_123", "publicKeyPem": "pem" }]
}
```

Notes:

- Implementations may verify by stored receipt ID (`receipt_id`) or by verifying an arbitrary receipt payload (`receipt`) using supplied public key(s).
- If a receipt chain is supplied, chain continuity is verified as well.

### Immutable Ledger

- `GET /admin/ledger/status`
- `GET /admin/ledger/entries?tenantId=<id>&limit=<n>&beforeSequence=<n>`
- `GET /admin/ledger/verify`
- `GET /admin/ledger/retention?tenantId=<id>`
- `POST /admin/ledger/retention`
- `POST /admin/ledger/retention/apply`

Purpose:

- Provide append-only ledger visibility and integrity verification for receipts and security events.

Response:

```json
{
  "is_signature_valid": true,
  "is_chain_valid": true,
  "is_schema_valid": true,
  "errors": []
}
```

### Backup And Disaster Recovery

- `GET /admin/backups/status`
- `GET /admin/backups?limit=<n>`
- `POST /admin/backups`
- `POST /admin/backups/restore`
- `GET /admin/backups/drills?limit=<n>`
- `POST /admin/backups/drills`

Purpose:

- Automate backup creation, validated restore workflows, and disaster recovery drill evidence generation.

Notes:

- Backup restore response includes `restartRequired: true`; service restart is required before resuming write traffic.
- Backup and drill operations are admin-only.

### Policy Management

- `POST /v1/policies`
- `POST /v1/policies/simulate`
- `GET /v1/policies/{policyId}`
- `POST /v1/policies/{policyId}/publish`
- `POST /v1/policies/{policyId}/rollback`

Policy rule matching supports:

- `toolIds`, `operations`, `targetContains`
- `riskTiers`
- `environments`, `requiredDataTypes`
- `timeWindowUtc` with wrap-around window support (start inclusive, end exclusive, UTC hours)

### Evidence Export

`POST /evidence/exports`

Request includes:

- framework (`eu_ai_act`, `iso_42001`, `soc2`)
- scope (tenant/system/time window)
- export format

Evidence bundle verification:

- `POST /evidence/exports/verify`

Evidence graph APIs:

- `GET /admin/evidence/graph/status?tenantId=<id>`
- `GET /admin/evidence/graph/nodes?tenantId=<id>&nodeType=<type>&page=<n>&pageSize=<n>`

Compliance mapping and coverage APIs:

- `GET /v1/admin/compliance/control-mappings?tenantId=<id>&framework=<framework>`
- `POST /v1/admin/compliance/control-mappings`
- `POST /v1/admin/compliance/coverage/scan`

### Tenant Administration

- `POST /tenants`
- `GET /admin/tenants`
- `POST /tenants/{tenant_id}/members`
- `GET /admin/tenants/{tenant_id}/approval-workflow`
- `POST /admin/tenants/{tenant_id}/approval-workflow`
- `POST /admin/approvals/escalations/scan`
- `GET /admin/tenants/{tenant_id}/keys`
- `POST /admin/tenants/{tenant_id}/keys/rotate`
- `GET /admin/tenants/{tenant_id}/vault/secrets`
- `POST /admin/tenants/{tenant_id}/vault/secrets`
- `GET /admin/security/mtls/status`
- `GET /admin/ops/dashboard?tenantId=<id>`
- `GET /admin/ops/alert-routing?tenantId=<id>`
- `POST /admin/ops/alert-routing`

### Trust Root Metadata

- `GET /trust/tenants/{tenant_id}/keys`

Purpose:

- Expose public verification keys and key lifecycle status for independent receipt verification clients.

## Error Model

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Action denied by policy rule R-104",
    "request_id": "req_123"
  }
}
```

## Security Requirements

- Mutating endpoints require scoped write permissions.
- Approval decisions require step-up auth for critical actions.
- Service-role tokens require trusted workload mTLS identity when workload identity enforcement is enabled.
- Sensitive payload fields are encrypted/tokenized before persistence.
