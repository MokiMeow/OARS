import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildServer } from "../src/api/server.js";
import { IdempotencyRetentionService } from "../src/core/services/idempotency-retention-service.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";

function createTimerHarness() {
  let callback: (() => void) | null = null;
  let active = false;
  const handle = { unref: vi.fn() };
  const setIntervalFn = vi.fn((next: () => void, _intervalMs: number) => {
    callback = next;
    active = true;
    return handle;
  });
  const clearIntervalFn = vi.fn((_handle: unknown) => {
    active = false;
  });

  return {
    handle,
    setIntervalFn,
    clearIntervalFn,
    fire() {
      if (active) {
        callback?.();
      }
    }
  };
}

describe("IdempotencyRetentionService", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
  });

  it("uses the exact injected cutoff and tracks prune counters", async () => {
    const pruneIdempotencyRecords = vi.fn().mockResolvedValueOnce(4).mockResolvedValueOnce(2);
    const service = new IdempotencyRetentionService(
      { pruneIdempotencyRecords },
      {
        ttlSeconds: 3_600,
        now: () => new Date("2026-07-22T00:00:00.000Z")
      }
    );

    await expect(service.runOnce()).resolves.toBe(4);
    expect(pruneIdempotencyRecords).toHaveBeenNthCalledWith(1, "2026-07-21T23:00:00.000Z");
    expect(service.status()).toEqual({
      running: false,
      lastRunAt: "2026-07-22T00:00:00.000Z",
      lastPrunedCount: 4,
      totalPrunedCount: 4,
      lastError: null
    });

    await expect(service.runOnce()).resolves.toBe(2);
    expect(service.status()).toMatchObject({ lastPrunedCount: 2, totalPrunedCount: 6, lastError: null });
  });

  it("falls back to safe TTL and interval defaults and unreferences its timer", async () => {
    const pruneIdempotencyRecords = vi.fn().mockResolvedValue(0);
    const timers = createTimerHarness();
    const service = new IdempotencyRetentionService(
      { pruneIdempotencyRecords },
      {
        ttlSeconds: 59,
        intervalSeconds: 29,
        now: () => new Date("2026-07-22T00:00:00.000Z"),
        setIntervalFn: timers.setIntervalFn,
        clearIntervalFn: timers.clearIntervalFn
      }
    );

    await service.runOnce();
    expect(pruneIdempotencyRecords).toHaveBeenCalledWith("2026-07-21T00:00:00.000Z");
    expect(service.start().running).toBe(true);
    expect(timers.setIntervalFn).toHaveBeenCalledWith(expect.any(Function), 3_600_000);
    expect(timers.handle.unref).toHaveBeenCalledTimes(1);
    expect(service.stop().running).toBe(false);
  });

  it("starts idempotently, suppresses overlapping runs, and stops future timer runs", async () => {
    let resolveFirst: ((count: number) => void) | undefined;
    const pruneIdempotencyRecords = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<number>((resolve) => {
            resolveFirst = resolve;
          })
      )
      .mockResolvedValue(1);
    const timers = createTimerHarness();
    const service = new IdempotencyRetentionService(
      { pruneIdempotencyRecords },
      {
        intervalSeconds: 30,
        setIntervalFn: timers.setIntervalFn,
        clearIntervalFn: timers.clearIntervalFn
      }
    );

    service.start();
    service.start();
    expect(timers.setIntervalFn).toHaveBeenCalledTimes(1);

    timers.fire();
    timers.fire();
    const sharedRun = service.runOnce();
    expect(pruneIdempotencyRecords).toHaveBeenCalledTimes(1);
    resolveFirst?.(2);
    await expect(sharedRun).resolves.toBe(2);

    timers.fire();
    await service.runOnce();
    expect(pruneIdempotencyRecords).toHaveBeenCalledTimes(2);

    service.stop();
    timers.fire();
    await Promise.resolve();
    expect(timers.clearIntervalFn).toHaveBeenCalledTimes(1);
    expect(pruneIdempotencyRecords).toHaveBeenCalledTimes(2);
  });

  it("captures non-secret errors and recovers on a later run", async () => {
    const pruneIdempotencyRecords = vi
      .fn()
      .mockRejectedValueOnce(new Error("postgres://secret-password@db"))
      .mockResolvedValueOnce(3);
    const service = new IdempotencyRetentionService({ pruneIdempotencyRecords });

    await expect(service.runOnce()).resolves.toBe(0);
    expect(service.status()).toMatchObject({
      lastPrunedCount: 0,
      totalPrunedCount: 0,
      lastError: "Idempotency retention prune failed."
    });
    expect(service.status().lastError).not.toContain("secret-password");

    await expect(service.runOnce()).resolves.toBe(3);
    expect(service.status()).toMatchObject({ lastPrunedCount: 3, totalPrunedCount: 3, lastError: null });
  });

  it("stops the server retention timer on close without leaving timer handles", async () => {
    vi.useFakeTimers();
    vi.stubEnv("OARS_IDEMPOTENCY_PRUNE_INTERVAL_SECONDS", "30");
    const baseDir = mkdtempSync(join(tmpdir(), "oars-idempotency-retention-"));
    const context = createPlatformContext({
      dataFilePath: join(baseDir, "state.json"),
      keyFilePath: join(baseDir, "keys.json"),
      ledgerFilePath: join(baseDir, "ledger.ndjson"),
      vaultFilePath: join(baseDir, "vault.json"),
      backupRootPath: join(baseDir, "backups"),
      drillReportsPath: join(baseDir, "drill-reports"),
      drillWorkspacePath: join(baseDir, "drill-workspace")
    });
    const pruneSpy = vi.spyOn(context.store, "pruneIdempotencyRecords");
    const app = buildServer(context);

    try {
      await app.ready();
      await vi.advanceTimersByTimeAsync(0);
      expect(pruneSpy).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBeGreaterThanOrEqual(2);

      await app.close();
      expect(vi.getTimerCount()).toBe(0);
      await vi.advanceTimersByTimeAsync(30_000);
      expect(pruneSpy).toHaveBeenCalledTimes(1);
    } finally {
      await app.close();
      rmSync(baseDir, { recursive: true, force: true });
    }
  });
});
