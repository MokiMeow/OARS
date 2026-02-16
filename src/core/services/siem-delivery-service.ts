import { createHmac } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { SecurityEventRecord } from "../types/domain.js";

type FetchLike = (input: string, init?: RequestInit) => Promise<{ ok: boolean; status: number; text: () => Promise<string> }>;

type BaseTarget = {
  id: string;
  enabled?: boolean | undefined;
};

type GenericWebhookTarget = BaseTarget & {
  type: "generic_webhook";
  url: string;
  headers?: Record<string, string> | undefined;
};

type SplunkTarget = BaseTarget & {
  type: "splunk_hec";
  url: string;
  token: string;
  source?: string | undefined;
  sourcetype?: string | undefined;
  index?: string | undefined;
  host?: string | undefined;
};

type DatadogTarget = BaseTarget & {
  type: "datadog_logs";
  apiKey: string;
  url?: string | undefined;
  source?: string | undefined;
  service?: string | undefined;
  host?: string | undefined;
  tags?: string[] | undefined;
};

type SentinelTarget = BaseTarget & {
  type: "sentinel_log_analytics";
  workspaceId: string;
  sharedKey: string;
  url?: string | undefined;
  logType?: string | undefined;
};

export type SiemTargetConfig = GenericWebhookTarget | SplunkTarget | DatadogTarget | SentinelTarget;

export interface SiemDeadLetterCandidate {
  targetId: string;
  event: SecurityEventRecord;
  attempts: number;
  lastError: string;
  failedAt: string;
}

interface TargetMetrics {
  successCount: number;
  failureCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastError: string | null;
}

interface RetryItem {
  targetId: string;
  event: SecurityEventRecord;
  attempts: number;
  nextAttemptAt: number;
  lastError: string;
}

interface SchedulerState {
  running: boolean;
  intervalSeconds: number;
  maxAttempts: number;
  inProgress: boolean;
  tickCount: number;
  lastRunAt: string | null;
  timer: NodeJS.Timeout | null;
}

export interface SiemDeliveryOptions {
  rawTargetsConfig?: string | undefined;
  targets?: SiemTargetConfig[] | undefined;
  fetchFn?: FetchLike | undefined;
  retryIntervalSeconds?: number | undefined;
  maxAttempts?: number | undefined;
  autoStartRetry?: boolean | undefined;
  onDeadLetter?: ((candidate: SiemDeadLetterCandidate) => Promise<void> | void) | undefined;
  queueFilePath?: string | undefined;
  maxQueueSize?: number | undefined;
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }
  return value.trim().toLowerCase() === "true";
}

function parseIntWithMin(value: string | undefined, fallback: number, min: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < min) {
    return fallback;
  }
  return parsed;
}

function normalizeTargets(options?: SiemDeliveryOptions): SiemTargetConfig[] {
  if (options?.targets && options.targets.length > 0) {
    return options.targets;
  }

  const raw = options?.rawTargetsConfig ?? process.env.OARS_SIEM_TARGETS;
  if (raw) {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (Array.isArray(parsed)) {
        return parsed as SiemTargetConfig[];
      }
    } catch {
      // Fall through to legacy env mapping.
    }
  }

  const legacyWebhook = process.env.OARS_SIEM_WEBHOOK_URL;
  if (legacyWebhook) {
    return [
      {
        id: "legacy_siem_webhook",
        type: "generic_webhook",
        url: legacyWebhook
      }
    ];
  }

  return [];
}

function endpointForSentinel(target: SentinelTarget): string {
  if (target.url) {
    return target.url;
  }
  return `https://${target.workspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`;
}

function sanitizeLogType(input: string): string {
  const clean = input.replace(/[^a-zA-Z0-9_]/g, "_");
  return clean.length > 0 ? clean : "OarsSecurityEvent";
}

export class SiemDeliveryService {
  private readonly targets: SiemTargetConfig[];
  private readonly fetchFn: FetchLike;
  private onDeadLetter: ((candidate: SiemDeadLetterCandidate) => Promise<void> | void) | undefined;
  private readonly metricsByTarget = new Map<string, TargetMetrics>();
  private retryQueue: RetryItem[] = [];
  private readonly queueFilePath: string;
  private readonly maxQueueSize: number;
  private droppedCount = 0;
  private backpressureDropCount = 0;
  private scheduler: SchedulerState;

  constructor(options?: SiemDeliveryOptions) {
    this.targets = normalizeTargets(options).filter((target) => target.enabled !== false);
    this.fetchFn = options?.fetchFn ?? (fetch as unknown as FetchLike);
    this.onDeadLetter = options?.onDeadLetter;
    this.queueFilePath = options?.queueFilePath ?? process.env.OARS_SIEM_RETRY_QUEUE_PATH ?? "data/siem-retry-queue.json";
    this.maxQueueSize = options?.maxQueueSize ?? parseIntWithMin(process.env.OARS_SIEM_RETRY_MAX_QUEUE_SIZE, 5000, 1);
    const intervalSeconds =
      options?.retryIntervalSeconds ?? parseIntWithMin(process.env.OARS_SIEM_RETRY_INTERVAL_SECONDS, 30, 5);
    const maxAttempts = options?.maxAttempts ?? parseIntWithMin(process.env.OARS_SIEM_RETRY_MAX_ATTEMPTS, 5, 1);
    this.scheduler = {
      running: false,
      intervalSeconds,
      maxAttempts,
      inProgress: false,
      tickCount: 0,
      lastRunAt: null,
      timer: null
    };

    for (const target of this.targets) {
      this.metricsByTarget.set(target.id, {
        successCount: 0,
        failureCount: 0,
        lastSuccessAt: null,
        lastFailureAt: null,
        lastError: null
      });
    }
    this.retryQueue = this.loadRetryQueue();

    const autoStart = options?.autoStartRetry ?? parseBoolean(process.env.OARS_SIEM_RETRY_AUTO_START, true);
    if (autoStart && this.targets.length > 0) {
      this.startRetryScheduler(intervalSeconds, maxAttempts);
    }
  }

  async deliver(event: SecurityEventRecord): Promise<void> {
    for (const target of this.targets) {
      const result = await this.sendToTarget(target, event);
      if (result.ok) {
        this.recordSuccess(target.id);
        continue;
      }
      this.recordFailure(target.id, result.error);
      this.enqueueRetry(target.id, event, result.error);
    }
  }

  setOnDeadLetter(handler: (candidate: SiemDeadLetterCandidate) => Promise<void> | void): void {
    this.onDeadLetter = handler;
  }

  status(): {
    targets: Array<{
      id: string;
      type: SiemTargetConfig["type"];
      enabled: boolean;
      successCount: number;
      failureCount: number;
      lastSuccessAt: string | null;
      lastFailureAt: string | null;
      lastError: string | null;
    }>;
    queueLength: number;
    droppedCount: number;
    maxQueueSize: number;
    backpressureDropCount: number;
    retry: {
      running: boolean;
      intervalSeconds: number;
      maxAttempts: number;
      inProgress: boolean;
      tickCount: number;
      lastRunAt: string | null;
    };
  } {
    return {
      targets: this.targets.map((target) => {
        const metrics = this.metricsByTarget.get(target.id);
        return {
          id: target.id,
          type: target.type,
          enabled: target.enabled !== false,
          successCount: metrics?.successCount ?? 0,
          failureCount: metrics?.failureCount ?? 0,
          lastSuccessAt: metrics?.lastSuccessAt ?? null,
          lastFailureAt: metrics?.lastFailureAt ?? null,
          lastError: metrics?.lastError ?? null
        };
      }),
      queueLength: this.retryQueue.length,
      droppedCount: this.droppedCount,
      maxQueueSize: this.maxQueueSize,
      backpressureDropCount: this.backpressureDropCount,
      retry: {
        running: this.scheduler.running,
        intervalSeconds: this.scheduler.intervalSeconds,
        maxAttempts: this.scheduler.maxAttempts,
        inProgress: this.scheduler.inProgress,
        tickCount: this.scheduler.tickCount,
        lastRunAt: this.scheduler.lastRunAt
      }
    };
  }

  startRetryScheduler(intervalSeconds?: number, maxAttempts?: number): {
    running: boolean;
    intervalSeconds: number;
    maxAttempts: number;
    inProgress: boolean;
    tickCount: number;
    lastRunAt: string | null;
  } {
    this.stopRetryScheduler();
    if (intervalSeconds) {
      this.scheduler.intervalSeconds = Math.max(5, intervalSeconds);
    }
    if (maxAttempts) {
      this.scheduler.maxAttempts = Math.max(1, maxAttempts);
    }
    this.scheduler.running = true;
    this.scheduler.timer = setInterval(() => {
      void this.processRetryQueue();
    }, this.scheduler.intervalSeconds * 1000);
    return this.status().retry;
  }

  stopRetryScheduler(): {
    running: boolean;
    intervalSeconds: number;
    maxAttempts: number;
    inProgress: boolean;
    tickCount: number;
    lastRunAt: string | null;
  } {
    if (this.scheduler.timer) {
      clearInterval(this.scheduler.timer);
      this.scheduler.timer = null;
    }
    this.scheduler.running = false;
    this.scheduler.inProgress = false;
    return this.status().retry;
  }

  async flushQueue(): Promise<{ processed: number; remaining: number }> {
    const processed = await this.processRetryQueue(true);
    return {
      processed,
      remaining: this.retryQueue.length
    };
  }

  private enqueueRetry(targetId: string, event: SecurityEventRecord, error: string): void {
    const existing = this.retryQueue.find((item) => item.targetId === targetId && item.event.id === event.id);
    if (existing) {
      existing.lastError = error;
      this.persistRetryQueue();
      return;
    }
    if (this.retryQueue.length >= this.maxQueueSize) {
      this.retryQueue.sort((a, b) => a.nextAttemptAt - b.nextAttemptAt);
      this.retryQueue.shift();
      this.droppedCount += 1;
      this.backpressureDropCount += 1;
    }
    this.retryQueue.push({
      targetId,
      event,
      attempts: 1,
      nextAttemptAt: Date.now() + this.scheduler.intervalSeconds * 1000,
      lastError: error
    });
    this.persistRetryQueue();
  }

  private async processRetryQueue(processAll = false): Promise<number> {
    if (this.scheduler.inProgress) {
      return 0;
    }
    this.scheduler.inProgress = true;
    this.scheduler.tickCount += 1;
    this.scheduler.lastRunAt = new Date().toISOString();

    let processed = 0;
    const now = Date.now();
    const queue = [...this.retryQueue];
    this.retryQueue.length = 0;

    for (const item of queue) {
      if (!processAll && item.nextAttemptAt > now) {
        this.retryQueue.push(item);
        continue;
      }

      const target = this.targets.find((entry) => entry.id === item.targetId);
      if (!target) {
        this.droppedCount += 1;
        continue;
      }

      const result = await this.sendToTarget(target, item.event);
      processed += 1;
      if (result.ok) {
        this.recordSuccess(target.id);
        continue;
      }

      this.recordFailure(target.id, result.error);
      item.attempts += 1;
      item.lastError = result.error;
      if (item.attempts >= this.scheduler.maxAttempts) {
        await this.handleDeadLetter(item);
        this.droppedCount += 1;
        continue;
      }

      const backoffMultiplier = Math.min(4, item.attempts);
      item.nextAttemptAt = Date.now() + this.scheduler.intervalSeconds * 1000 * backoffMultiplier;
      this.retryQueue.push(item);
    }

    this.scheduler.inProgress = false;
    this.persistRetryQueue();
    return processed;
  }

  async replayToTarget(targetId: string, event: SecurityEventRecord): Promise<{ ok: boolean; error: string }> {
    const target = this.targets.find((entry) => entry.id === targetId);
    if (!target) {
      return {
        ok: false,
        error: `Target not found: ${targetId}`
      };
    }

    const result = await this.sendToTarget(target, event);
    if (result.ok) {
      this.recordSuccess(target.id);
    } else {
      this.recordFailure(target.id, result.error);
    }
    return result;
  }

  private recordSuccess(targetId: string): void {
    const metrics = this.metricsByTarget.get(targetId);
    if (!metrics) {
      return;
    }
    metrics.successCount += 1;
    metrics.lastSuccessAt = new Date().toISOString();
    metrics.lastError = null;
  }

  private recordFailure(targetId: string, error: string): void {
    const metrics = this.metricsByTarget.get(targetId);
    if (!metrics) {
      return;
    }
    metrics.failureCount += 1;
    metrics.lastFailureAt = new Date().toISOString();
    metrics.lastError = error;
  }

  private async sendToTarget(
    target: SiemTargetConfig,
    event: SecurityEventRecord
  ): Promise<{ ok: boolean; error: string }> {
    if (target.type === "generic_webhook") {
      return this.sendGenericWebhook(target, event);
    }
    if (target.type === "splunk_hec") {
      return this.sendSplunk(target, event);
    }
    if (target.type === "datadog_logs") {
      return this.sendDatadog(target, event);
    }
    return this.sendSentinel(target, event);
  }

  private async sendGenericWebhook(
    target: GenericWebhookTarget,
    event: SecurityEventRecord
  ): Promise<{ ok: boolean; error: string }> {
    try {
      const response = await this.fetchFn(target.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(target.headers ?? {})
        },
        body: JSON.stringify(event)
      });
      if (!response.ok) {
        return { ok: false, error: `HTTP ${response.status}: ${await response.text()}` };
      }
      return { ok: true, error: "" };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Generic webhook exception." };
    }
  }

  private async sendSplunk(
    target: SplunkTarget,
    event: SecurityEventRecord
  ): Promise<{ ok: boolean; error: string }> {
    const payload = {
      time: Math.floor(Date.parse(event.occurredAt) / 1000),
      host: target.host ?? "oars-platform",
      source: target.source ?? "oars",
      sourcetype: target.sourcetype ?? "oars:security:event",
      index: target.index,
      event
    };
    try {
      const response = await this.fetchFn(target.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Splunk ${target.token}`
        },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        return { ok: false, error: `HTTP ${response.status}: ${await response.text()}` };
      }
      return { ok: true, error: "" };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Splunk delivery exception." };
    }
  }

  private async sendDatadog(
    target: DatadogTarget,
    event: SecurityEventRecord
  ): Promise<{ ok: boolean; error: string }> {
    const url = target.url ?? "https://http-intake.logs.datadoghq.com/v1/input";
    const payload = [
      {
        message: `${event.eventType} (${event.id})`,
        ddsource: target.source ?? "oars",
        service: target.service ?? "oars-platform",
        hostname: target.host ?? "oars-host",
        ddtags: target.tags?.join(",") ?? "",
        oars_event: event
      }
    ];
    try {
      const response = await this.fetchFn(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "DD-API-KEY": target.apiKey
        },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        return { ok: false, error: `HTTP ${response.status}: ${await response.text()}` };
      }
      return { ok: true, error: "" };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Datadog delivery exception." };
    }
  }

  private async sendSentinel(
    target: SentinelTarget,
    event: SecurityEventRecord
  ): Promise<{ ok: boolean; error: string }> {
    const url = endpointForSentinel(target);
    const payload = JSON.stringify([
      {
        EventId: event.id,
        TenantId: event.tenantId,
        Source: event.source,
        EventType: event.eventType,
        OccurredAt: event.occurredAt,
        Payload: event.payload
      }
    ]);
    const dateHeader = new Date().toUTCString();
    const contentLength = Buffer.byteLength(payload, "utf8");
    const stringToSign = `POST\n${contentLength}\napplication/json\nx-ms-date:${dateHeader}\n/api/logs`;
    let signature = "";
    try {
      signature = createHmac("sha256", Buffer.from(target.sharedKey, "base64"))
        .update(stringToSign, "utf8")
        .digest("base64");
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Sentinel signature error." };
    }

    try {
      const response = await this.fetchFn(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-ms-date": dateHeader,
          "Log-Type": sanitizeLogType(target.logType ?? "OarsSecurityEvent"),
          Authorization: `SharedKey ${target.workspaceId}:${signature}`
        },
        body: payload
      });
      if (!response.ok) {
        return { ok: false, error: `HTTP ${response.status}: ${await response.text()}` };
      }
      return { ok: true, error: "" };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : "Sentinel delivery exception." };
    }
  }

  private async handleDeadLetter(item: RetryItem): Promise<void> {
    if (!this.onDeadLetter) {
      return;
    }
    await this.onDeadLetter({
      targetId: item.targetId,
      event: item.event,
      attempts: item.attempts,
      lastError: item.lastError,
      failedAt: new Date().toISOString()
    });
  }

  private loadRetryQueue(): RetryItem[] {
    if (!existsSync(this.queueFilePath)) {
      return [];
    }
    try {
      const raw = readFileSync(this.queueFilePath, "utf8");
      const parsed = JSON.parse(raw) as RetryItem[];
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed
        .map((item) => ({
          targetId: item.targetId,
          event: item.event,
          attempts: Math.max(1, item.attempts),
          nextAttemptAt: item.nextAttemptAt,
          lastError: item.lastError
        }))
        .filter((item) => Boolean(item.targetId) && Boolean(item.event?.id));
    } catch {
      return [];
    }
  }

  private persistRetryQueue(): void {
    const folder = dirname(this.queueFilePath);
    if (!existsSync(folder)) {
      mkdirSync(folder, { recursive: true });
    }
    writeFileSync(this.queueFilePath, JSON.stringify(this.retryQueue, null, 2), "utf8");
  }
}
