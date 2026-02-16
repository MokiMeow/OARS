import { afterEach, describe, expect, it } from "vitest";
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

const cleanupQueue: Array<{ ctx: ReturnType<typeof createPlatformContext>; baseDir: string }> = [];

afterEach(async () => {
  const items = cleanupQueue.splice(0, cleanupQueue.length);
  for (const item of items) {
    await item.ctx.store.close?.();
    cleanup([item.baseDir]);
  }
});

function makeContext(): ReturnType<typeof createPlatformContext> {
  const suffix = createId("test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const ctx = createPlatformContext({
    dataFilePath: join(baseDir, `${suffix}-state.json`),
    keyFilePath: join(baseDir, `${suffix}-keys.json`),
    ledgerFilePath: join(baseDir, `${suffix}-ledger.ndjson`),
    vaultFilePath: join(baseDir, `${suffix}-vault.json`)
  });
  cleanupQueue.push({ ctx, baseDir });
  return ctx;
}

describe("EvidenceGraphService", () => {
  it("returns an empty snapshot for a new tenant", async () => {
    const ctx = makeContext();
    const snapshot = await ctx.evidenceGraphService.snapshot("tenant_alpha");
    expect(snapshot.tenantId).toBe("tenant_alpha");
    expect(snapshot.edgeCount).toBe(0);
  });

  it("lists nodes by type with pagination", async () => {
    const ctx = makeContext();
    const nodes = await ctx.evidenceGraphService.listNodes("tenant_alpha", "all", 1, 50);
    expect(nodes.items).toEqual([]);
  });
});

describe("ControlMappingService", () => {
  it("creates a control mapping", async () => {
    const ctx = makeContext();
    const mapping = await ctx.controlMappingService.upsertMapping({
      tenantId: "tenant_alpha",
      framework: "soc2",
      controlId: "CC6.1",
      controlDescription: "Logical Access",
      requiredNodeTypes: ["action", "receipt"],
      actor: "admin_user"
    });
    expect(mapping.framework).toBe("soc2");
    expect(mapping.controlId).toBe("CC6.1");
  });

  it("lists mappings by framework", async () => {
    const ctx = makeContext();
    await ctx.controlMappingService.upsertMapping({
      tenantId: "tenant_alpha",
      framework: "soc2",
      controlId: "CC6.1",
      controlDescription: "Logical Access",
      requiredNodeTypes: ["action", "receipt"],
      actor: "admin_user"
    });
    await ctx.controlMappingService.upsertMapping({
      tenantId: "tenant_alpha",
      framework: "eu_ai_act",
      controlId: "ART-14",
      controlDescription: "Human Oversight",
      requiredNodeTypes: ["approval_decision"],
      actor: "admin_user"
    });

    const soc2 = await ctx.controlMappingService.listMappings("tenant_alpha", "soc2");
    expect(soc2.length).toBe(1);
    expect(soc2[0]?.controlId).toBe("CC6.1");
  });

  it("scans coverage and detects missing evidence", async () => {
    const ctx = makeContext();
    await ctx.controlMappingService.upsertMapping({
      tenantId: "tenant_alpha",
      framework: "soc2",
      controlId: "CC6.1",
      controlDescription: "Logical Access",
      requiredNodeTypes: ["action", "receipt"],
      actor: "admin_user"
    });

    const coverage = await ctx.controlMappingService.scanCoverage("tenant_alpha", "soc2");
    expect(coverage.totalControls).toBe(1);
    expect(coverage.missingControls.length).toBeGreaterThan(0);
  });
});
