import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileExecutionBackplane } from "../src/core/backplane/execution-backplane.js";

describe("FileExecutionBackplane", () => {
  it("enqueues, claims, completes, and enforces inflight idempotency", async () => {
    const baseDir = mkdtempSync(join(tmpdir(), "oars-backplane-"));
    const queuePath = join(baseDir, "queue.json");
    try {
      const backplane = new FileExecutionBackplane(queuePath, { lockTimeoutSeconds: 1, maxAttempts: 1 });
      const job1 = await backplane.enqueue({ tenantId: "tenant_alpha", actionId: "act_1", requestId: "req_1" });
      const job2 = await backplane.enqueue({ tenantId: "tenant_alpha", actionId: "act_1", requestId: "req_1" });
      expect(job2.id).toBe(job1.id);

      const claimed = await backplane.claim("worker_a", 10);
      expect(claimed).toHaveLength(1);
      expect(claimed[0]!.id).toBe(job1.id);

      await backplane.complete(job1.id, "worker_a");
      const after = await backplane.claim("worker_a", 10);
      expect(after).toHaveLength(0);
    } finally {
      rmSync(baseDir, { force: true, recursive: true });
    }
  });

  it("retries until maxAttempts and then dead-letters", async () => {
    const baseDir = mkdtempSync(join(tmpdir(), "oars-backplane-"));
    const queuePath = join(baseDir, "queue.json");
    try {
      const backplane = new FileExecutionBackplane(queuePath, { lockTimeoutSeconds: 1, maxAttempts: 2 });
      const job = await backplane.enqueue({ tenantId: "tenant_alpha", actionId: "act_retry", requestId: "req_1" });

      const first = await backplane.claim("worker_a", 1);
      expect(first).toHaveLength(1);
      await backplane.fail(job.id, "worker_a", "boom", 0);

      const second = await backplane.claim("worker_a", 1);
      expect(second).toHaveLength(1);
      const updated = await backplane.fail(job.id, "worker_a", "boom2", 0);
      expect(updated?.status).toBe("dead");
    } finally {
      rmSync(baseDir, { force: true, recursive: true });
    }
  });
});

