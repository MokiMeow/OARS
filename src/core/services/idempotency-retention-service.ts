import type { PlatformStore } from "../store/platform-store.js";

const DEFAULT_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_INTERVAL_SECONDS = 60 * 60;
const MIN_TTL_SECONDS = 60;
const MIN_INTERVAL_SECONDS = 30;

type RetentionStore = Pick<PlatformStore, "pruneIdempotencyRecords">;
type SetIntervalLike = (callback: () => void, intervalMs: number) => unknown;
type ClearIntervalLike = (handle: unknown) => void;

export interface IdempotencyRetentionServiceOptions {
  ttlSeconds?: number | undefined;
  intervalSeconds?: number | undefined;
  now?: (() => Date) | undefined;
  setIntervalFn?: SetIntervalLike | undefined;
  clearIntervalFn?: ClearIntervalLike | undefined;
}

export interface IdempotencyRetentionStatus {
  running: boolean;
  lastRunAt: string | null;
  lastPrunedCount: number;
  totalPrunedCount: number;
  lastError: string | null;
}

function validatedSeconds(value: number | undefined, fallback: number, minimum: number): number {
  if (value === undefined || !Number.isInteger(value) || value < minimum) {
    return fallback;
  }
  return value;
}

function defaultSetInterval(callback: () => void, intervalMs: number): unknown {
  return setInterval(callback, intervalMs);
}

function defaultClearInterval(handle: unknown): void {
  clearInterval(handle as ReturnType<typeof setInterval>);
}

function unrefTimer(handle: unknown): void {
  if (!handle || (typeof handle !== "object" && typeof handle !== "function")) {
    return;
  }
  const unref = (handle as { unref?: (() => unknown) | undefined }).unref;
  if (typeof unref === "function") {
    unref.call(handle);
  }
}

export class IdempotencyRetentionService {
  private readonly ttlSeconds: number;
  private readonly intervalSeconds: number;
  private readonly now: () => Date;
  private readonly setIntervalFn: SetIntervalLike;
  private readonly clearIntervalFn: ClearIntervalLike;
  private timer: unknown | null = null;
  private activeRun: Promise<number> | null = null;
  private lastRunAt: string | null = null;
  private lastPrunedCount = 0;
  private totalPrunedCount = 0;
  private lastError: string | null = null;

  constructor(
    private readonly store: RetentionStore,
    options?: IdempotencyRetentionServiceOptions
  ) {
    this.ttlSeconds = validatedSeconds(options?.ttlSeconds, DEFAULT_TTL_SECONDS, MIN_TTL_SECONDS);
    this.intervalSeconds = validatedSeconds(
      options?.intervalSeconds,
      DEFAULT_INTERVAL_SECONDS,
      MIN_INTERVAL_SECONDS
    );
    this.now = options?.now ?? (() => new Date());
    this.setIntervalFn = options?.setIntervalFn ?? defaultSetInterval;
    this.clearIntervalFn = options?.clearIntervalFn ?? defaultClearInterval;
  }

  runOnce(): Promise<number> {
    if (this.activeRun) {
      return this.activeRun;
    }

    const run = (async () => {
      try {
        const runAt = this.now();
        this.lastRunAt = runAt.toISOString();
        const cutoff = new Date(runAt.getTime() - this.ttlSeconds * 1_000).toISOString();
        const prunedCount = await this.store.pruneIdempotencyRecords(cutoff);
        this.lastPrunedCount = prunedCount;
        this.totalPrunedCount += prunedCount;
        this.lastError = null;
        return prunedCount;
      } catch {
        this.lastPrunedCount = 0;
        this.lastError = "Idempotency retention prune failed.";
        return 0;
      }
    })();

    this.activeRun = run;
    void run.finally(() => {
      if (this.activeRun === run) {
        this.activeRun = null;
      }
    });
    return run;
  }

  start(): IdempotencyRetentionStatus {
    if (this.timer !== null) {
      return this.status();
    }
    this.timer = this.setIntervalFn(() => {
      void this.runOnce();
    }, this.intervalSeconds * 1_000);
    unrefTimer(this.timer);
    return this.status();
  }

  stop(): IdempotencyRetentionStatus {
    if (this.timer !== null) {
      this.clearIntervalFn(this.timer);
      this.timer = null;
    }
    return this.status();
  }

  status(): IdempotencyRetentionStatus {
    return {
      running: this.timer !== null,
      lastRunAt: this.lastRunAt,
      lastPrunedCount: this.lastPrunedCount,
      totalPrunedCount: this.totalPrunedCount,
      lastError: this.lastError
    };
  }
}
