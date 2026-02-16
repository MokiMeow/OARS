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
    context,
    baseDir
  };
}

describeDocker("OARS API (Postgres store + backplane queue)", () => {
  it("queues action execution and worker processes it", async () => {
    const prevMode = process.env.OARS_BACKPLANE_MODE;
    const prevDriver = process.env.OARS_BACKPLANE_DRIVER;
    const prevAttempts = process.env.OARS_BACKPLANE_MAX_ATTEMPTS;
    process.env.OARS_BACKPLANE_MODE = "queue";
    process.env.OARS_BACKPLANE_DRIVER = "postgres";
    process.env.OARS_BACKPLANE_MAX_ATTEMPTS = "1";

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

    const { app, context, baseDir } = createTestServer({
      storeMode: "postgres",
      postgresUrl
    });

    try {
      const actionResponse = await app.inject({
        method: "POST",
        url: "/v1/actions",
        headers: {
          ...adminAuthHeader,
          "Idempotency-Key": "idem_queue_1"
        },
        payload: {
          tenantId: "tenant_alpha",
          agentId: "agent_queue",
          userContext: { userId: "user_queue" },
          resource: {
            toolId: "jira",
            operation: "create_ticket",
            target: "project:SEC"
          },
          input: {
            summary: "Queued action"
          }
        }
      });

      expect(actionResponse.statusCode).toBe(202);
      const actionBody = actionResponse.json() as { actionId: string; state: string; receiptId: string };
      expect(actionBody.state).toBe("approved");

      const backplane = context.executionBackplane;
      expect(backplane).toBeTruthy();
      const claimed = await backplane!.claim("worker_test", 5);
      expect(claimed.length).toBeGreaterThanOrEqual(1);

      const job = claimed.find((entry) => entry.actionId === actionBody.actionId);
      expect(job).toBeTruthy();
      const result = await context.actionService.executeApprovedAction(actionBody.actionId, job!.requestId);
      expect(result.state).toBe("executed");
      await backplane!.complete(job!.id, "worker_test");

      const actionRead = await app.inject({
        method: "GET",
        url: `/v1/actions/${actionBody.actionId}`,
        headers: adminAuthHeader
      });
      expect(actionRead.statusCode).toBe(200);
      const actionReadBody = actionRead.json() as { action: { state: string } };
      expect(actionReadBody.action.state).toBe("executed");
    } finally {
      await app.close();
      await postgres.stop();
      cleanup([baseDir]);
      process.env.OARS_BACKPLANE_MODE = prevMode;
      process.env.OARS_BACKPLANE_DRIVER = prevDriver;
      process.env.OARS_BACKPLANE_MAX_ATTEMPTS = prevAttempts;
    }
  }, 120_000);
});

