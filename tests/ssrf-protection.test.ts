import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";

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

function createTestServer() {
  const suffix = createId("test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const dataFilePath = join(baseDir, `${suffix}-state.json`);
  const keyFilePath = join(baseDir, `${suffix}-keys.json`);
  const ledgerFilePath = join(baseDir, `${suffix}-ledger.ndjson`);
  const vaultFilePath = join(baseDir, `${suffix}-vault.json`);
  const backupRootPath = join(baseDir, `${suffix}-backups`);
  const drillReportsPath = join(baseDir, `${suffix}-drill-reports`);
  const drillWorkspacePath = join(baseDir, `${suffix}-drill-workspace`);
  const context = createPlatformContext({
    dataFilePath,
    keyFilePath,
    ledgerFilePath,
    vaultFilePath,
    backupRootPath,
    drillReportsPath,
    drillWorkspacePath
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

describe("SSRF / target sandbox protection", () => {
  it("blocks private and metadata targets in execution path", async () => {
    await withEnv({ OARS_RATE_LIMIT_RPM: "0" }, async () => {
      const { app, baseDir, dataFilePath, keyFilePath, ledgerFilePath, vaultFilePath, backupRootPath, drillReportsPath, drillWorkspacePath } =
        createTestServer();
      try {
        const targets = [
          "http://10.0.0.1",
          "http://172.16.0.1",
          "http://192.168.0.1",
          "http://127.0.0.1",
          "http://169.254.169.254",
          "http://[::1]",
          "http://[fd00::1]",
          "http://[fe80::1]",
          "http://[::ffff:127.0.0.1]"
        ];

        for (const target of targets) {
          const response = await app.inject({
            method: "POST",
            url: "/v1/actions",
            headers: adminAuthHeader,
            payload: {
              tenantId: "tenant_alpha",
              agentId: "agent_ssrf",
              resource: {
                toolId: "jira",
                operation: "create_ticket",
                target
              },
              input: {
                summary: "SSRF test"
              }
            }
          });
          expect(response.statusCode).toBe(202);
          const body = response.json() as { state: string; error?: string | null };
          expect(body.state).toBe("failed");
          expect(body.error).toContain("sandbox target policy");
        }
      } finally {
        await app.close();
        cleanup([baseDir, dataFilePath, keyFilePath, ledgerFilePath, vaultFilePath, backupRootPath, drillReportsPath, drillWorkspacePath]);
      }
    });
  }, 60_000);
});
