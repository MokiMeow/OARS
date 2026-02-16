import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { SecurityEventRecord, SiemDeadLetterRecord } from "../types/domain.js";
import { ImmutableLedgerService } from "./immutable-ledger-service.js";
import { SiemDeliveryService, type SiemDeadLetterCandidate } from "./siem-delivery-service.js";

interface PublishSecurityEventInput {
  tenantId: string;
  source: "receipt" | "alert" | "admin";
  eventType: string;
  payload: Record<string, unknown>;
}

export class SecurityEventService {
  constructor(
    private readonly store: PlatformStore,
    private readonly siemDeliveryService: SiemDeliveryService,
    private readonly filePath = process.env.OARS_SIEM_FILE_PATH,
    private readonly immutableLedgerService?: ImmutableLedgerService
  ) {
    this.siemDeliveryService.setOnDeadLetter(async (candidate) => {
      await this.persistDeadLetter(candidate);
    });
  }

  async publish(input: PublishSecurityEventInput): Promise<SecurityEventRecord> {
    const event: SecurityEventRecord = {
      id: createId("evt"),
      tenantId: input.tenantId,
      source: input.source,
      eventType: input.eventType,
      occurredAt: nowIso(),
      payload: input.payload
    };

    this.immutableLedgerService?.appendSecurityEvent(event);
    await this.store.saveSecurityEvent(event);
    this.appendToFile(event);
    await this.siemDeliveryService.deliver(event);
    return event;
  }

  async listByTenant(tenantId: string, limit = 200): Promise<SecurityEventRecord[]> {
    return this.store.listSecurityEventsByTenant(tenantId, limit);
  }

  siemStatus(): ReturnType<SiemDeliveryService["status"]> {
    return this.siemDeliveryService.status();
  }

  async flushSiemQueue(): Promise<ReturnType<SiemDeliveryService["flushQueue"]>> {
    return this.siemDeliveryService.flushQueue();
  }

  startSiemRetryScheduler(
    intervalSeconds?: number,
    maxAttempts?: number
  ): ReturnType<SiemDeliveryService["startRetryScheduler"]> {
    return this.siemDeliveryService.startRetryScheduler(intervalSeconds, maxAttempts);
  }

  stopSiemRetryScheduler(): ReturnType<SiemDeliveryService["stopRetryScheduler"]> {
    return this.siemDeliveryService.stopRetryScheduler();
  }

  async listSiemDeadLetters(
    tenantId: string,
    status: SiemDeadLetterRecord["status"] | "all",
    page = 1,
    pageSize = 100
  ) {
    return this.store.listSiemDeadLettersPaged(tenantId, status, page, pageSize);
  }

  async replaySiemDeadLetter(deadLetterId: string): Promise<{
    deadLetter: SiemDeadLetterRecord;
    replaySucceeded: boolean;
    replayError: string | null;
  }> {
    const deadLetter = await this.store.getSiemDeadLetter(deadLetterId);
    if (!deadLetter) {
      throw new Error(`Dead letter not found: ${deadLetterId}`);
    }
    return this.replaySiemDeadLetterForTenant(deadLetter.tenantId, deadLetterId);
  }

  async replaySiemDeadLetterForTenant(
    tenantId: string,
    deadLetterId: string
  ): Promise<{
    deadLetter: SiemDeadLetterRecord;
    replaySucceeded: boolean;
    replayError: string | null;
  }> {
    const deadLetter = await this.store.getSiemDeadLetterForTenant(deadLetterId, tenantId);
    if (!deadLetter) {
      throw new Error(`Dead letter not found for tenant: ${deadLetterId}`);
    }

    const event: SecurityEventRecord = {
      id: deadLetter.eventId,
      tenantId: deadLetter.tenantId,
      source: deadLetter.source,
      eventType: deadLetter.eventType,
      occurredAt: deadLetter.occurredAt,
      payload: deadLetter.payload
    };
    const replayResult = await this.siemDeliveryService.replayToTarget(deadLetter.targetId, event);

    deadLetter.replayCount += 1;
    deadLetter.updatedAt = nowIso();
    if (replayResult.ok) {
      deadLetter.status = "replayed";
      deadLetter.lastError = "";
    } else {
      deadLetter.status = "open";
      deadLetter.lastError = replayResult.error;
    }
    await this.store.saveSiemDeadLetter(deadLetter);

    await this.publish({
      tenantId: deadLetter.tenantId,
      source: "admin",
      eventType: "siem.dead_letter.replay",
      payload: {
        deadLetterId: deadLetter.id,
        targetId: deadLetter.targetId,
        replaySucceeded: replayResult.ok,
        replayError: replayResult.ok ? null : replayResult.error
      }
    });

    return {
      deadLetter,
      replaySucceeded: replayResult.ok,
      replayError: replayResult.ok ? null : replayResult.error
    };
  }

  async resolveSiemDeadLetter(deadLetterId: string): Promise<SiemDeadLetterRecord> {
    const deadLetter = await this.store.getSiemDeadLetter(deadLetterId);
    if (!deadLetter) {
      throw new Error(`Dead letter not found: ${deadLetterId}`);
    }
    return this.resolveSiemDeadLetterForTenant(deadLetter.tenantId, deadLetterId);
  }

  async resolveSiemDeadLetterForTenant(tenantId: string, deadLetterId: string): Promise<SiemDeadLetterRecord> {
    const deadLetter = await this.store.getSiemDeadLetterForTenant(deadLetterId, tenantId);
    if (!deadLetter) {
      throw new Error(`Dead letter not found for tenant: ${deadLetterId}`);
    }
    deadLetter.status = "resolved";
    deadLetter.updatedAt = nowIso();
    await this.store.saveSiemDeadLetter(deadLetter);
    return deadLetter;
  }

  private appendToFile(event: SecurityEventRecord): void {
    if (!this.filePath) {
      return;
    }

    const parent = dirname(this.filePath);
    if (!existsSync(parent)) {
      mkdirSync(parent, { recursive: true });
    }
    appendFileSync(this.filePath, `${JSON.stringify(event)}\n`, "utf8");
  }

  private async persistDeadLetter(candidate: SiemDeadLetterCandidate): Promise<void> {
    const record: SiemDeadLetterRecord = {
      id: createId("dlq"),
      targetId: candidate.targetId,
      tenantId: candidate.event.tenantId,
      eventId: candidate.event.id,
      eventType: candidate.event.eventType,
      source: candidate.event.source,
      occurredAt: candidate.event.occurredAt,
      payload: candidate.event.payload,
      attempts: candidate.attempts,
      lastError: candidate.lastError,
      failedAt: candidate.failedAt,
      replayCount: 0,
      status: "open",
      updatedAt: nowIso()
    };
    await this.store.saveSiemDeadLetter(record);
  }
}
