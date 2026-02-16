import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { createId } from "../src/lib/id.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";

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
  for (const candidate of paths) {
    if (existsSync(candidate)) {
      rmSync(candidate, { force: true, recursive: true });
    }
  }
}

function makeContext() {
  const suffix = createId("test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const ctx = createPlatformContext({
    dataFilePath: join(baseDir, `${suffix}-state.json`),
    keyFilePath: join(baseDir, `${suffix}-keys.json`),
    ledgerFilePath: join(baseDir, `${suffix}-ledger.ndjson`),
    vaultFilePath: join(baseDir, `${suffix}-vault.json`)
  });
  return { ctx, cleanupPaths: [baseDir] };
}

describe("ApprovalService", () => {
  it("creates a pending approval with default stages", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      const approval = await ctx.approvalService.createPendingApproval(createId("act"), "tenant_alpha", false);
      expect(approval.status).toBe("pending");
      expect(approval.tenantId).toBe("tenant_alpha");
      expect(approval.stages.length).toBeGreaterThan(0);
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });

  it("records an approve decision", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      const actionId = createId("act");
      const approval = await ctx.approvalService.createPendingApproval(actionId, "tenant_alpha", false);
      const result = await ctx.approvalService.recordDecision(approval.id, "approve", "admin_user", "Looks good");
      expect(result.status).toBe("approved");
      expect(result.decisions.length).toBeGreaterThan(0);
      expect(result.decisions[0]?.decision).toBe("approve");
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });

  it("records a reject decision", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      const actionId = createId("act");
      const approval = await ctx.approvalService.createPendingApproval(actionId, "tenant_alpha", false);
      const result = await ctx.approvalService.recordDecision(approval.id, "reject", "admin_user", "Too risky");
      expect(result.status).toBe("rejected");
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });

  it("throws on decision for unknown approval", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      await expect(ctx.approvalService.recordDecision("nonexistent", "approve", "admin_user", "reason")).rejects.toThrow();
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });

  it("throws on decision for already-decided approval", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      const actionId = createId("act");
      const approval = await ctx.approvalService.createPendingApproval(actionId, "tenant_alpha", false);
      await ctx.approvalService.recordDecision(approval.id, "approve", "admin_user", "ok");
      await expect(ctx.approvalService.recordDecision(approval.id, "reject", "another_user", "nope")).rejects.toThrow();
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });

  it("scans for escalations returns array", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      const result = await ctx.approvalService.scanForEscalations("tenant_alpha");
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });

  it("creates approval with step-up requirement", async () => {
    const { ctx, cleanupPaths } = makeContext();
    try {
      const approval = await ctx.approvalService.createPendingApproval(createId("act"), "tenant_alpha", true);
      expect(approval.requiresStepUp).toBe(true);
    } finally {
      await ctx.store.close?.();
      cleanup(cleanupPaths);
    }
  });
});
