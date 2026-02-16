import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";
import { OarsClient } from "../src/sdk/index.js";
import type { PlatformContextOptions } from "../src/core/services/platform-context.js";

function cleanup(paths: string[]): void {
  const tmpRoot = resolve(tmpdir());
  const tempDirs = new Set<string>();
  for (const candidate of paths) {
    const resolved = resolve(candidate);
    if (!resolved.startsWith(tmpRoot + sep)) {
      continue;
    }
    const suffix = resolved.slice(tmpRoot.length + sep.length);
    const firstSegment = suffix.split(sep)[0];
    if (firstSegment && firstSegment.startsWith("oars-sdk_test_")) {
      tempDirs.add(join(tmpRoot, firstSegment));
    }
  }
  for (const dir of tempDirs) {
    if (existsSync(dir)) {
      rmSync(dir, { force: true, recursive: true });
    }
  }
  for (const path of paths) {
    if (existsSync(path)) {
      rmSync(path, { force: true, recursive: true });
    }
  }
}

function createTestServer(options?: PlatformContextOptions) {
  const suffix = createId("sdk_test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const dataFilePath = join(baseDir, `${suffix}-state.json`);
  const keyFilePath = join(baseDir, `${suffix}-keys.json`);
  const ledgerFilePath = join(baseDir, `${suffix}-ledger.ndjson`);
  const vaultFilePath = join(baseDir, `${suffix}-vault.json`);
  const backupRootPath = options?.backupRootPath ?? join(baseDir, `${suffix}-backups`);
  const drillReportsPath = options?.drillReportsPath ?? join(baseDir, `${suffix}-drill-reports`);
  const drillWorkspacePath = options?.drillWorkspacePath ?? join(baseDir, `${suffix}-drill-workspace`);
  const context = createPlatformContext({
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    backupRootPath,
    drillReportsPath,
    drillWorkspacePath,
    ...options
  });
  const app = buildServer(context);
  return {
    app,
    cleanupPaths: [baseDir]
  };
}

function createInjectFetch(app: { inject: (opts: any) => Promise<any> }): typeof fetch {
  return (async (input: any, init?: any) => {
    const urlString = typeof input === "string" ? input : String(input?.url ?? input);
    const url = new URL(urlString, "http://localhost");
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const payload = init?.body ? JSON.parse(String(init.body)) : undefined;
    const injected = await app.inject({
      method,
      url: `${url.pathname}${url.search}`,
      headers,
      payload
    });

    const responseHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(injected.headers ?? {})) {
      if (typeof value === "string") {
        responseHeaders[key] = value;
      } else if (Array.isArray(value) && typeof value[0] === "string") {
        responseHeaders[key] = value[0];
      } else if (value !== undefined) {
        responseHeaders[key] = String(value);
      }
    }

    return new Response(injected.body, {
      status: injected.statusCode,
      headers: responseHeaders
    });
  }) as unknown as typeof fetch;
}

describe("OARS SDK", () => {
  it("wraps action submission, idempotency replay, receipt verification, and receipt listing", async () => {
    const { app, cleanupPaths } = createTestServer();
    try {
      const client = new OarsClient({
        baseUrl: "http://localhost",
        token: "dev_admin_token",
        fetchFn: createInjectFetch(app),
        maxRetries: 0
      });

      const first = await client.submitAction(
        {
          tenantId: "tenant_alpha",
          agentId: "agent_sdk",
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
            summary: "SDK submit"
          }
        },
        { idempotencyKey: "sdk-idem-1" }
      );
      expect(first.actionId).toMatch(/^act_/);
      expect(first.receiptId).toMatch(/^rcpt_/);

      const replay = await client.submitAction(
        {
          tenantId: "tenant_alpha",
          agentId: "agent_sdk",
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
            summary: "SDK submit"
          }
        },
        { idempotencyKey: "sdk-idem-1" }
      );
      expect(replay.actionId).toBe(first.actionId);
      expect(replay.receiptId).toBe(first.receiptId);

      const action = await client.getAction(first.actionId);
      expect(action.action.id).toBe(first.actionId);
      expect(Array.isArray(action.receipts)).toBe(true);
      expect(action.receipts.length).toBeGreaterThan(0);

      const verify = await client.verifyReceipt({ receiptId: first.receiptId });
      expect(verify.isSchemaValid).toBe(true);
      expect(verify.isSignatureValid).toBe(true);

      const receipts = await client.listReceipts({ tenantId: "tenant_alpha", limit: 50 });
      expect(receipts.tenantId).toBe("tenant_alpha");
      expect(receipts.items.length).toBeGreaterThan(0);
    } finally {
      await app.close();
      cleanup(cleanupPaths);
    }
  });
});
