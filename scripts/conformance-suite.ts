import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";

interface ConformanceAssertion {
  check: string;
  passed: boolean;
  details?: string | undefined;
}

function cleanup(paths: string[]): void {
  for (const path of paths) {
    if (existsSync(path)) {
      rmSync(path, { recursive: true, force: true });
    }
  }
}

async function main(): Promise<void> {
  const suffix = createId("conf");
  const dataFilePath = join("data", `${suffix}-state.json`);
  const keyFilePath = join("data", `${suffix}-keys.json`);
  const ledgerFilePath = join("data", `${suffix}-ledger.ndjson`);
  const vaultFilePath = join("data", `${suffix}-vault.json`);
  const context = createPlatformContext({
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    siemOptions: {
      autoStartRetry: false
    }
  });
  const app = buildServer(context);
  const assertions: ConformanceAssertion[] = [];
  try {
    const health = await app.inject({
      method: "GET",
      url: "/health"
    });
    assertions.push({
      check: "health_endpoint",
      passed: health.statusCode === 200
    });

    const unauthorizedConnectors = await app.inject({
      method: "GET",
      url: "/v1/connectors"
    });
    assertions.push({
      check: "auth_enforcement",
      passed: unauthorizedConnectors.statusCode === 401,
      details: `status=${unauthorizedConnectors.statusCode}`
    });

    const action = await app.inject({
      method: "POST",
      url: "/v1/actions",
      headers: {
        authorization: "Bearer dev_admin_token"
      },
      payload: {
        tenantId: "tenant_alpha",
        agentId: "agent_conformance",
        resource: {
          toolId: "jira",
          operation: "create_ticket",
          target: "project:SEC"
        },
        input: {
          summary: "Conformance execution test"
        }
      }
    });
    const actionPayload = action.json();
    assertions.push({
      check: "action_submission",
      passed: action.statusCode === 202 && Boolean(actionPayload.actionId) && Boolean(actionPayload.receiptId)
    });

    const verify = await app.inject({
      method: "POST",
      url: "/v1/receipts/verify",
      headers: {
        authorization: "Bearer dev_admin_token"
      },
      payload: {
        receiptId: actionPayload.receiptId
      }
    });
    const verifyPayload = verify.json();
    assertions.push({
      check: "receipt_verification",
      passed:
        verify.statusCode === 200 &&
        verifyPayload.isSignatureValid === true &&
        verifyPayload.isChainValid === true &&
        verifyPayload.isSchemaValid === true
    });

    const failed = assertions.filter((assertion) => !assertion.passed);
    process.stdout.write(`${JSON.stringify({ assertions, failedCount: failed.length }, null, 2)}\n`);
    if (failed.length > 0) {
      process.exitCode = 1;
    }
  } finally {
    await app.close();
    cleanup([dataFilePath, keyFilePath, ledgerFilePath, vaultFilePath]);
  }
}

void main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Conformance suite failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
