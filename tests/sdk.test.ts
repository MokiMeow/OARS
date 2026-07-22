import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";
import { OarsClient, OarsHttpError, type ActionSubmission } from "../src/sdk/index.js";
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

const testActionSubmission: ActionSubmission = {
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
    summary: "SDK retry test"
  }
};

describe("OARS SDK", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

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

  it.each([
    { status: 401, code: "unauthorized" },
    { status: 404, code: "not_found" }
  ])("does not retry a structured $status HTTP response", async ({ status, code }) => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ error: { code, message: "Request failed", requestId: "req_structured" } }), {
        status,
        headers: { "content-type": "application/json" }
      })
    );
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      maxRetries: 2
    });

    const error = await client.getAction("missing").catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(OarsHttpError);
    expect(error).toMatchObject({ status, code, requestId: "req_structured" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("retries a previously omitted 5xx response and then succeeds", async () => {
    vi.useFakeTimers();
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 501 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ action: { id: "act_retry" }, receipts: [] }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
      );
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      maxRetries: 1
    });

    const request = client.getAction("act_retry");
    await vi.advanceTimersByTimeAsync(200);

    await expect(request).resolves.toMatchObject({ action: { id: "act_retry" } });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("retries a network failure and then succeeds", async () => {
    vi.useFakeTimers();
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new TypeError("network unavailable"))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ action: { id: "act_network" }, receipts: [] }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
      );
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      maxRetries: 1
    });

    const request = client.getAction("act_network");
    await vi.advanceTimersByTimeAsync(200);

    await expect(request).resolves.toMatchObject({ action: { id: "act_network" } });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("keeps response body consumption bounded by timeout and safe retry limits", async () => {
    vi.useFakeTimers();
    const fetchFn = vi.fn<typeof fetch>(async (_input, init) => {
      const signal = init?.signal;
      const responseBody = new ReadableStream<Uint8Array>({
        start(controller) {
          const abort = () => controller.error(new DOMException("The operation was aborted.", "AbortError"));
          if (signal?.aborted) {
            abort();
          } else {
            signal?.addEventListener("abort", abort, { once: true });
          }
        }
      });
      return new Response(responseBody, {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    });
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      timeoutMs: 100,
      maxRetries: 1
    });

    const request = client.getAction("act_stalled_body");
    const rejection = expect(request).rejects.toMatchObject({ name: "AbortError" });

    await vi.advanceTimersByTimeAsync(99);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await vi.advanceTimersByTimeAsync(199);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(100);

    await rejection;
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("does not retry a transient response for action submission without an idempotency key", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 503 }));
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      maxRetries: 2
    });

    const error = await client.submitAction(testActionSubmission).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(OarsHttpError);
    expect(error).toMatchObject({ status: 503, code: "http_error" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("does not retry a transport failure for action submission without an idempotency key", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("network unavailable"));
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      maxRetries: 2
    });

    const error = await client.submitAction(testActionSubmission).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(TypeError);
    expect(error).toMatchObject({ message: "network unavailable" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it.each([
    { label: "delta seconds", retryAfter: "2", expectedDelayMs: 2_000 },
    { label: "HTTP date", retryAfter: "Tue, 01 Jan 2030 00:00:05 GMT", expectedDelayMs: 5_000 },
    { label: "malformed value", retryAfter: "later", expectedDelayMs: 200 },
    { label: "negative value", retryAfter: "-1", expectedDelayMs: 200 },
    { label: "capped value", retryAfter: "60", expectedDelayMs: 30_000 }
  ])("uses the expected delay for a $label Retry-After header", async ({ retryAfter, expectedDelayMs }) => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00.000Z"));
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 503, headers: { "retry-after": retryAfter } }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ action: { id: "act_retry_after" }, receipts: [] }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
      );
    const client = new OarsClient({
      baseUrl: "http://localhost",
      token: "test-token",
      fetchFn,
      maxRetries: 1
    });

    const request = client.getAction("act_retry_after");
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(expectedDelayMs - 1);
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1);
    await expect(request).resolves.toMatchObject({ action: { id: "act_retry_after" } });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});
