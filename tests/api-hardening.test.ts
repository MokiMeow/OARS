import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";
import type { PlatformContextOptions } from "../src/core/services/platform-context.js";

const adminAuthHeader = {
  authorization: "Bearer dev_admin_token"
};

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
    if (firstSegment && firstSegment.startsWith("oars-test_")) {
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

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const before: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    before[key] = process.env[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  return fn().finally(() => {
    for (const [key, value] of Object.entries(before)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });
}

function createTestServer(options?: PlatformContextOptions) {
  const suffix = createId("test");
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
    baseDir,
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    backupRootPath,
    drillReportsPath,
    drillWorkspacePath
  };
}

describe("API hardening", () => {
  it("applies security response headers", async () => {
    const { app, dataFilePath, keyFilePath } = createTestServer();
    try {
      const response = await app.inject({ method: "GET", url: "/health" });
      expect(response.statusCode).toBe(200);
      expect(response.headers["x-content-type-options"]).toBe("nosniff");
      expect(response.headers["x-frame-options"]).toBe("DENY");
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.headers["x-xss-protection"]).toBe("0");
      expect(typeof response.headers["x-request-id"]).toBe("string");
    } finally {
      await app.close();
      cleanup([dataFilePath, keyFilePath]);
    }
  });

  it("rate limits requests per token and skips /health", async () => {
    await withEnv({ OARS_RATE_LIMIT_RPM: "3" }, async () => {
      const { app, dataFilePath, keyFilePath } = createTestServer();
      try {
        const ok1 = await app.inject({ method: "GET", url: "/v1/connectors", headers: adminAuthHeader });
        const ok2 = await app.inject({ method: "GET", url: "/v1/connectors", headers: adminAuthHeader });
        const ok3 = await app.inject({ method: "GET", url: "/v1/connectors", headers: adminAuthHeader });
        const blocked = await app.inject({ method: "GET", url: "/v1/connectors", headers: adminAuthHeader });
        expect(ok1.statusCode).toBe(200);
        expect(ok2.statusCode).toBe(200);
        expect(ok3.statusCode).toBe(200);
        expect(blocked.statusCode).toBe(429);
        expect(blocked.headers["x-ratelimit-limit"]).toBe("3");

        for (let i = 0; i < 10; i += 1) {
          const health = await app.inject({ method: "GET", url: "/health" });
          expect(health.statusCode).toBe(200);
        }
      } finally {
        await app.close();
        cleanup([dataFilePath, keyFilePath]);
      }
    });
  });

  it("enforces CORS preflight origin checks when configured", async () => {
    await withEnv({ OARS_CORS_ORIGINS: "https://app.example.com", OARS_RATE_LIMIT_RPM: "0" }, async () => {
      const { app, dataFilePath, keyFilePath } = createTestServer();
      try {
        const allowed = await app.inject({
          method: "OPTIONS",
          url: "/v1/connectors",
          headers: {
            origin: "https://app.example.com",
            "access-control-request-method": "GET"
          }
        });
        expect(allowed.statusCode).toBe(204);
        expect(allowed.headers["access-control-allow-origin"]).toBe("https://app.example.com");

        const denied = await app.inject({
          method: "OPTIONS",
          url: "/v1/connectors",
          headers: {
            origin: "https://evil.example.com",
            "access-control-request-method": "GET"
          }
        });
        expect(denied.statusCode).toBe(403);
        expect((denied.json() as { error?: { code?: string } }).error?.code).toBe("cors_forbidden");
      } finally {
        await app.close();
        cleanup([dataFilePath, keyFilePath]);
      }
    });
  });

  it("rejects oversized request bodies", async () => {
    await withEnv({ OARS_BODY_LIMIT_BYTES: "250", OARS_RATE_LIMIT_RPM: "0" }, async () => {
      const { app, dataFilePath, keyFilePath } = createTestServer();
      try {
        const bigPayload = JSON.stringify({
          tenantId: "tenant_alpha",
          agentId: "agent_big",
          resource: { toolId: "jira", operation: "create_ticket", target: "project:SEC" },
          input: { blob: "x".repeat(5000) }
        });

        await app.listen({ port: 0, host: "127.0.0.1" });
        const address = app.server.address();
        if (!address || typeof address === "string") {
          throw new Error("Unexpected server address binding.");
        }
        const response = await fetch(`http://127.0.0.1:${address.port}/v1/actions`, {
          method: "POST",
          headers: {
            ...adminAuthHeader,
            "content-type": "application/json"
          },
          body: bigPayload
        });
        expect(response.status).toBe(413);
      } finally {
        await app.close();
        cleanup([dataFilePath, keyFilePath]);
      }
    });
  });
});
