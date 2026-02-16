import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { GenericContainer, Wait } from "testcontainers";
import { buildServer } from "../src/api/server.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { createId } from "../src/lib/id.js";
import type { PlatformContextOptions } from "../src/core/services/platform-context.js";

const adminAuthHeader = {
  authorization: "Bearer dev_admin_token"
};

const describeDocker = process.env.OARS_DOCKER_TESTS === "1" ? describe : describe.skip;

function cleanup(paths: string[]): void {
  for (const path of paths) {
    if (existsSync(path)) {
      rmSync(path, { force: true, recursive: true });
    }
  }
}

function createTestServer(options?: PlatformContextOptions) {
  const suffix = createId("test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const keyFilePath = join(baseDir, `${suffix}-keys.json`);
  const ledgerFilePath = join(baseDir, `${suffix}-ledger.ndjson`);
  const vaultFilePath = join(baseDir, `${suffix}-vault.json`);
  const backupRootPath = options?.backupRootPath ?? join(baseDir, `${suffix}-backups`);
  const drillReportsPath = options?.drillReportsPath ?? join(baseDir, `${suffix}-drill-reports`);
  const drillWorkspacePath = options?.drillWorkspacePath ?? join(baseDir, `${suffix}-drill-workspace`);
  const context = createPlatformContext({
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
    baseDir
  };
}

describeDocker("OARS API (Postgres store)", () => {
  it("executes action flow and verifies receipts end-to-end", async () => {
    const postgres = await new GenericContainer("postgres:16-alpine")
      .withExposedPorts(5432)
      .withEnvironment({
        POSTGRES_PASSWORD: "postgres",
        POSTGRES_USER: "postgres",
        POSTGRES_DB: "oars"
      })
      .withWaitStrategy(Wait.forListeningPorts())
      .start();

    const host = postgres.getHost();
    const port = postgres.getMappedPort(5432);
    const postgresUrl = `postgres://postgres:postgres@${host}:${port}/oars`;

    const { app, baseDir } = createTestServer({
        storeMode: "postgres",
        postgresUrl
      });

    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          ...adminAuthHeader,
          "Idempotency-Key": "idem_pg_1"
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_pg",
          userContext: { userId: "user_pg" },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Postgres store action"
          }
        }
      });

      expect(actionResponse.statusCode).toBe(202);
      const actionBody = actionResponse.json() as { actionId: string; state: string; receiptId: string };
      expect(actionBody.actionId).toMatch(/^act_/);
      expect(actionBody.receiptId).toMatch(/^rcpt_/);
      expect(actionBody.state).toBe("executed");

      const actionRead = await app.inject({
        method: "GET",
        url: `/v1/actions/${actionBody.actionId}`,
        headers: adminAuthHeader
      });
      expect(actionRead.statusCode).toBe(200);
      const actionReadBody = actionRead.json() as { receipts: { id: string }[] };
      expect(actionReadBody.receipts.length).toBeGreaterThanOrEqual(2);

      const verify = await app.inject({
        method: "POST",
        url: "/v1/receipts/verify",
        headers: adminAuthHeader,
        payload: {
          receiptId: actionBody.receiptId
        }
      });
      expect(verify.statusCode).toBe(200);
      const verifyBody = verify.json() as { isSignatureValid: boolean; isChainValid: boolean; isSchemaValid: boolean };
      expect(verifyBody.isSignatureValid).toBe(true);
      expect(verifyBody.isChainValid).toBe(true);
      expect(verifyBody.isSchemaValid).toBe(true);

      const replay = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          ...adminAuthHeader,
          "Idempotency-Key": "idem_pg_1"
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_pg",
          userContext: { userId: "user_pg" },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Postgres store action"
          }
        }
      });
      expect(replay.statusCode).toBe(202);
      const replayBody = replay.json() as { actionId: string };
      expect(replayBody.actionId).toBe(actionBody.actionId);
    } finally {
      await app.close();
      await postgres.stop();
      cleanup([baseDir]);
    }
  }, 120_000);
});
