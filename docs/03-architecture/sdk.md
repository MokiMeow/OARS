# Embedded SDK

OARS includes an embedded TypeScript SDK that can be consumed as a package subpath export.

## Import

After building (`npm run build`), import from:

- `oars-platform/sdk`

## Example

```ts
import { OarsClient } from "oars-platform/sdk";

const client = new OarsClient({
  baseUrl: "http://localhost:8080",
  token: "dev_admin_token"
});

const result = await client.submitAction(
  {
    tenantId: "tenant_alpha",
    agentId: "agent_finops_01",
    context: {
      environment: "prod",
      dataTypes: ["pii"]
    },
    resource: {
      toolId: "jira",
      operation: "create_ticket",
      target: "project:SEC"
    },
    input: {
      summary: "Investigate suspicious traffic"
    }
  },
  { idempotencyKey: "my-stable-key-123" }
);

const action = await client.getAction(result.actionId);
const receipts = await client.listReceipts({ tenantId: "tenant_alpha", limit: 50 });
const verification = await client.verifyReceipt({ receiptId: result.receiptId });
```

## Behavior

- Auth: sends `Authorization: Bearer <token>`.
- Idempotency: sends `Idempotency-Key` when provided; the SDK only retries `submitAction` when an idempotency key is set.
- Retries: `GET` and receipt verification are retried by default on transient HTTP errors (timeouts/429/5xx), configurable via `maxRetries`.
- Timeouts: configurable via `timeoutMs`.

