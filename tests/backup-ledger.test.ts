import { describe, expect, it, afterEach } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createId } from "../src/lib/id.js";
import { ImmutableLedgerService } from "../src/core/services/immutable-ledger-service.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import type { ActionReceipt, SecurityEventRecord } from "../src/core/types/domain.js";

const testDataDir = mkdtempSync(join(tmpdir(), "oars-backup-ledger-"));

function ensureDir(dir: string) {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function cleanDir(dir: string) {
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

function makeSecurityEvent(tenantId: string): SecurityEventRecord {
  return {
    id: createId("evt"),
    tenantId,
    source: "admin",
    eventType: "test.event",
    occurredAt: new Date().toISOString(),
    payload: { test: true }
  };
}

describe("ImmutableLedgerService", () => {
  afterEach(() => {
    cleanDir(testDataDir);
  });

  it("appends security events and maintains chain", () => {
    ensureDir(testDataDir);
    const ledgerPath = join(testDataDir, `ledger-${createId("t")}.ndjson`);
    const ledger = new ImmutableLedgerService(ledgerPath);

    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));
    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));

    const s = ledger.status();
    expect(s.totalEntries).toBe(2);
  });

  it("verifies integrity of valid chain", () => {
    ensureDir(testDataDir);
    const ledgerPath = join(testDataDir, `ledger-${createId("t")}.ndjson`);
    const ledger = new ImmutableLedgerService(ledgerPath);

    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));
    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));

    const verification = ledger.verifyIntegrity();
    expect(verification.isValid).toBe(true);
    expect(verification.checkedEntries).toBe(2);
    expect(verification.errors.length).toBe(0);
  });

  it("detects tampered entries on startup", () => {
    ensureDir(testDataDir);
    const ledgerPath = join(testDataDir, `ledger-${createId("t")}.ndjson`);
    const ledger = new ImmutableLedgerService(ledgerPath);

    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));
    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));

    // Tamper with the ledger file
    const { readFileSync: readFs } = require("node:fs") as typeof import("node:fs");
    const content = readFs(ledgerPath, "utf8");
    const lines = content.trim().split("\n");
    if (lines.length >= 2 && lines[1]) {
      const entry = JSON.parse(lines[1]) as Record<string, unknown>;
      entry.payloadHash = "tampered_hash_value";
      lines[1] = JSON.stringify(entry);
      writeFileSync(ledgerPath, lines.join("\n") + "\n", "utf8");
    }

    // Tampered ledger should throw on startup verification
    expect(() => new ImmutableLedgerService(ledgerPath)).toThrow("verification failed");
  });

  it("lists entries filtered by tenant", () => {
    ensureDir(testDataDir);
    const ledgerPath = join(testDataDir, `ledger-${createId("t")}.ndjson`);
    const ledger = new ImmutableLedgerService(ledgerPath);

    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));
    ledger.appendSecurityEvent(makeSecurityEvent("tenant_bravo"));
    ledger.appendSecurityEvent(makeSecurityEvent("tenant_alpha"));

    const result = ledger.listEntriesByTenant("tenant_alpha", 100);
    expect(result.items.length).toBe(2);
  });
});

describe("BackupRecoveryService", () => {
  afterEach(() => {
    cleanDir(testDataDir);
  });

  it("creates a backup and lists it in catalog", async () => {
    ensureDir(testDataDir);
    const suffix = createId("bak");
    const ctx = createPlatformContext({
      dataFilePath: join(testDataDir, `${suffix}-state.json`),
      keyFilePath: join(testDataDir, `${suffix}-keys.json`),
      ledgerFilePath: join(testDataDir, `${suffix}-ledger.ndjson`),
      vaultFilePath: join(testDataDir, `${suffix}-vault.json`),
      backupRootPath: join(testDataDir, `backups-${suffix}`),
      drillReportsPath: join(testDataDir, `drills-${suffix}`),
      drillWorkspacePath: join(testDataDir, `drill-ws-${suffix}`)
    });

    const backup = ctx.backupRecoveryService.createBackup("test_user", "test_backup");
    expect(backup.reason).toBe("test_backup");
    expect(backup.files.length).toBeGreaterThan(0);

    const catalog = ctx.backupRecoveryService.listBackups(10);
    expect(catalog.length).toBe(1);
    expect(catalog[0]?.backupId).toBe(backup.backupId);
  });
});

describe("LedgerGovernanceService", () => {
  afterEach(() => {
    cleanDir(testDataDir);
  });

  it("returns default retention policy for unknown tenant", async () => {
    ensureDir(testDataDir);
    const suffix = createId("lg");
    const ctx = createPlatformContext({
      dataFilePath: join(testDataDir, `${suffix}-state.json`),
      keyFilePath: join(testDataDir, `${suffix}-keys.json`),
      ledgerFilePath: join(testDataDir, `${suffix}-ledger.ndjson`),
      vaultFilePath: join(testDataDir, `${suffix}-vault.json`)
    });

    const policy = await ctx.ledgerGovernanceService.getPolicy("tenant_alpha");
    expect(policy.retentionDays).toBe(365);
    expect(policy.legalHold).toBe(false);
  });
});
