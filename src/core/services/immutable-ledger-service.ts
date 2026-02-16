import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalStringify } from "../../lib/canonical-json.js";
import { sha256Hex } from "../../lib/hash.js";
import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import type { ActionReceipt, SecurityEventRecord } from "../types/domain.js";

type LedgerEntityType = "receipt" | "security_event";

interface ImmutableLedgerEntry {
  entryId: string;
  sequence: number;
  tenantId: string;
  entityType: LedgerEntityType;
  entityId: string;
  occurredAt: string;
  appendedAt: string;
  prevEntryHash: string | null;
  payloadHash: string;
  entryHash: string;
  payload: Record<string, unknown>;
}

function normalizeRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as Record<string, unknown>;
}

export class ImmutableLedgerService {
  private readonly filePath: string;
  private entries: ImmutableLedgerEntry[];

  constructor(filePath = process.env.OARS_IMMUTABLE_LEDGER_PATH ?? "data/immutable-ledger.ndjson") {
    this.filePath = filePath;
    this.entries = this.readEntriesFromDisk();
    const startupVerification = this.validateEntries(this.entries);
    if (!startupVerification.isValid) {
      throw new Error(
        `Immutable ledger verification failed on startup: ${startupVerification.errors.join("; ")}`
      );
    }
  }

  appendReceipt(receipt: ActionReceipt): ImmutableLedgerEntry {
    return this.append(
      "receipt",
      receipt.tenantId,
      receipt.receiptId,
      receipt.timestamp,
      normalizeRecord(receipt as unknown)
    );
  }

  appendSecurityEvent(event: SecurityEventRecord): ImmutableLedgerEntry {
    return this.append(
      "security_event",
      event.tenantId,
      event.id,
      event.occurredAt,
      normalizeRecord(event as unknown)
    );
  }

  listEntriesByTenant(
    tenantId: string,
    limit = 100,
    beforeSequence?: number
  ): { items: ImmutableLedgerEntry[]; total: number } {
    const filtered = this.entries
      .filter((entry) => entry.tenantId === tenantId)
      .filter((entry) => (beforeSequence ? entry.sequence < beforeSequence : true))
      .sort((a, b) => b.sequence - a.sequence);
    const safeLimit = Math.min(500, Math.max(1, limit));
    return {
      items: filtered.slice(0, safeLimit),
      total: filtered.length
    };
  }

  status(): {
    path: string;
    totalEntries: number;
    lastSequence: number;
    lastEntryHash: string | null;
  } {
    const last = this.entries.at(-1);
    return {
      path: this.filePath,
      totalEntries: this.entries.length,
      lastSequence: last?.sequence ?? 0,
      lastEntryHash: last?.entryHash ?? null
    };
  }

  verifyIntegrity(): {
    isValid: boolean;
    checkedEntries: number;
    lastSequence: number;
    lastEntryHash: string | null;
    errors: string[];
  } {
    const entriesFromDisk = this.readEntriesFromDisk();
    const validation = this.validateEntries(entriesFromDisk);
    return {
      isValid: validation.isValid,
      checkedEntries: entriesFromDisk.length,
      lastSequence: entriesFromDisk.at(-1)?.sequence ?? 0,
      lastEntryHash: entriesFromDisk.at(-1)?.entryHash ?? null,
      errors: validation.errors
    };
  }

  pruneTenantEntries(
    tenantId: string,
    retentionDays: number,
    now = nowIso()
  ): {
    tenantId: string;
    cutoffTime: string;
    prunedCount: number;
    remainingCount: number;
    archivePath: string;
  } {
    const nowMs = Date.parse(now);
    if (Number.isNaN(nowMs)) {
      throw new Error("Invalid retention timestamp.");
    }
    const safeRetentionDays = Math.max(1, retentionDays);
    const cutoffMs = nowMs - safeRetentionDays * 24 * 60 * 60 * 1000;
    const cutoffTime = new Date(cutoffMs).toISOString();

    const prune: ImmutableLedgerEntry[] = [];
    const keep: ImmutableLedgerEntry[] = [];
    for (const entry of this.entries) {
      const occurredMs = Date.parse(entry.occurredAt);
      const shouldPrune =
        entry.tenantId === tenantId && !Number.isNaN(occurredMs) && occurredMs < cutoffMs;
      if (shouldPrune) {
        prune.push(entry);
      } else {
        keep.push(entry);
      }
    }

    const archivePath = `${this.filePath}.archive.ndjson`;
    if (prune.length > 0) {
      this.ensureParentFolder();
      for (const entry of prune) {
        appendFileSync(archivePath, `${JSON.stringify(entry)}\n`, "utf8");
      }
    }

    const rebuilt = this.rebuildEntries(keep);
    writeFileSync(this.filePath, rebuilt.map((entry) => JSON.stringify(entry)).join("\n") + (rebuilt.length ? "\n" : ""), "utf8");
    this.entries = rebuilt;

    return {
      tenantId,
      cutoffTime,
      prunedCount: prune.length,
      remainingCount: rebuilt.filter((entry) => entry.tenantId === tenantId).length,
      archivePath
    };
  }

  private append(
    entityType: LedgerEntityType,
    tenantId: string,
    entityId: string,
    occurredAt: string,
    payload: Record<string, unknown>
  ): ImmutableLedgerEntry {
    const previous = this.entries.at(-1);
    const sequence = (previous?.sequence ?? 0) + 1;
    const appendedAt = nowIso();
    const prevEntryHash = previous?.entryHash ?? null;
    const payloadHash = sha256Hex(canonicalStringify(payload));
    const entryHash = sha256Hex(
      canonicalStringify({
        sequence,
        tenantId,
        entityType,
        entityId,
        occurredAt,
        appendedAt,
        prevEntryHash,
        payloadHash
      })
    );

    const entry: ImmutableLedgerEntry = {
      entryId: createId("ldg"),
      sequence,
      tenantId,
      entityType,
      entityId,
      occurredAt,
      appendedAt,
      prevEntryHash,
      payloadHash,
      entryHash,
      payload
    };

    this.ensureParentFolder();
    appendFileSync(this.filePath, `${JSON.stringify(entry)}\n`, "utf8");
    this.entries.push(entry);
    return entry;
  }

  private ensureParentFolder(): void {
    const parent = dirname(this.filePath);
    if (!existsSync(parent)) {
      mkdirSync(parent, { recursive: true });
    }
  }

  private readEntriesFromDisk(): ImmutableLedgerEntry[] {
    if (!existsSync(this.filePath)) {
      return [];
    }

    const lines = readFileSync(this.filePath, "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const entries: ImmutableLedgerEntry[] = [];
    for (const line of lines) {
      const parsed = JSON.parse(line) as Partial<ImmutableLedgerEntry>;
      const payload = normalizeRecord(parsed.payload);
      entries.push({
        entryId: parsed.entryId ?? createId("ldg_unknown"),
        sequence: parsed.sequence ?? 0,
        tenantId: parsed.tenantId ?? "",
        entityType: parsed.entityType === "security_event" ? "security_event" : "receipt",
        entityId: parsed.entityId ?? "",
        occurredAt: parsed.occurredAt ?? "",
        appendedAt: parsed.appendedAt ?? "",
        prevEntryHash: parsed.prevEntryHash ?? null,
        payloadHash: parsed.payloadHash ?? "",
        entryHash: parsed.entryHash ?? "",
        payload
      });
    }

    return entries.sort((a, b) => a.sequence - b.sequence);
  }

  private validateEntries(entries: ImmutableLedgerEntry[]): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    for (let index = 0; index < entries.length; index += 1) {
      const current = entries[index];
      if (!current) {
        continue;
      }
      const expectedSequence = index + 1;
      if (current.sequence !== expectedSequence) {
        errors.push(`Invalid sequence at index ${index}: expected ${expectedSequence} got ${current.sequence}.`);
      }

      const recomputedPayloadHash = sha256Hex(canonicalStringify(current.payload));
      if (recomputedPayloadHash !== current.payloadHash) {
        errors.push(`Payload hash mismatch at sequence ${current.sequence}.`);
      }

      const previous = entries[index - 1];
      if (!previous) {
        if (current.prevEntryHash !== null) {
          errors.push("First ledger entry has non-null prevEntryHash.");
        }
      } else if (current.prevEntryHash !== previous.entryHash) {
        errors.push(`Broken entry chain at sequence ${current.sequence}.`);
      }

      const recomputedEntryHash = sha256Hex(
        canonicalStringify({
          sequence: current.sequence,
          tenantId: current.tenantId,
          entityType: current.entityType,
          entityId: current.entityId,
          occurredAt: current.occurredAt,
          appendedAt: current.appendedAt,
          prevEntryHash: current.prevEntryHash,
          payloadHash: current.payloadHash
        })
      );
      if (recomputedEntryHash !== current.entryHash) {
        errors.push(`Entry hash mismatch at sequence ${current.sequence}.`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  private rebuildEntries(entries: ImmutableLedgerEntry[]): ImmutableLedgerEntry[] {
    const rebuilt: ImmutableLedgerEntry[] = [];
    for (let index = 0; index < entries.length; index += 1) {
      const source = entries[index];
      if (!source) {
        continue;
      }
      const sequence = index + 1;
      const prevEntryHash = rebuilt[index - 1]?.entryHash ?? null;
      const payloadHash = sha256Hex(canonicalStringify(source.payload));
      const entryHash = sha256Hex(
        canonicalStringify({
          sequence,
          tenantId: source.tenantId,
          entityType: source.entityType,
          entityId: source.entityId,
          occurredAt: source.occurredAt,
          appendedAt: source.appendedAt,
          prevEntryHash,
          payloadHash
        })
      );
      rebuilt.push({
        ...source,
        sequence,
        prevEntryHash,
        payloadHash,
        entryHash
      });
    }
    return rebuilt;
  }
}
