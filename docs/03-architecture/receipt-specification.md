# Receipt Specification

## Objective

Define a portable, signed, verifiable receipt for each agent action state transition.

## Receipt Types

- `action.requested`
- `action.denied`
- `action.approval_required`
- `action.approved`
- `action.executed`
- `action.failed`
- `action.quarantined`
- `action.canceled`

## Required Fields

```json
{
  "receipt_id": "uuid",
  "version": "1.0.0",
  "tenant_id": "string",
  "action_id": "string",
  "type": "action.executed",
  "timestamp": "RFC3339",
  "actor": {
    "user_id": "string|null",
    "agent_id": "string",
    "service_id": "string|null",
    "delegation_chain": ["string"]
  },
  "resource": {
    "tool_id": "string",
    "operation": "string",
    "target": "string"
  },
  "policy": {
    "policy_set_id": "string",
    "policy_version": "string",
    "decision": "allow|deny|approve|quarantine",
    "rule_ids": ["string"],
    "rationale": "string"
  },
  "risk": {
    "score": 0,
    "tier": "low|medium|high|critical",
    "signals": ["string"]
  },
  "integrity": {
    "prev_receipt_hash": "hex|null",
    "receipt_hash": "hex",
    "signature": "base64",
    "signing_key_id": "string",
    "signature_alg": "Ed25519"
  },
  "telemetry": {
    "trace_id": "string",
    "span_id": "string",
    "request_id": "string"
  }
}
```

## Canonicalization Rules

- JSON canonicalization is required before hashing and signing.
- Field ordering must follow canonical serializer implementation.
- Signature verification must fail on non-canonical payload mutation.

## Hash Chain Rules

- `prev_receipt_hash` references the immediate predecessor for the same `action_id`.
- First receipt in chain has `prev_receipt_hash = null`.
- Chain verification fails if any link is missing or altered.

## Signing Rules

- Signing keys are tenant-scoped with rotation support.
- Key ID must resolve to active or historical trusted public key.
- Expired keys remain valid for historical verification.

## Privacy And Redaction

- Sensitive content fields are not stored in raw form by default.
- Receipt payload supports tokenized references to secured evidence blobs.
- Redaction policy IDs must be included in receipt metadata.

## Validation Rules

- `receipt_id` must be globally unique.
- `action_id` must remain stable across all receipt types for the action.
- `timestamp` must be monotonic within an action chain.
- `policy.decision` must match receipt type state.

## Verification API Contract

Input:

- receipt payload
- expected trust root

Output:

- `is_signature_valid`
- `is_chain_valid`
- `is_schema_valid`
- `verification_errors[]`

## Versioning Policy

- Semantic versioning for schema.
- Minor versions add backward-compatible fields.
- Major versions can alter field semantics with migration guidance.

