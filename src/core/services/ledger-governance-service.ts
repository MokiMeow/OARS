import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { LedgerRetentionPolicyRecord } from "../types/domain.js";
import { ImmutableLedgerService } from "./immutable-ledger-service.js";
import { SecurityEventService } from "./security-event-service.js";

export class LedgerGovernanceService {
  constructor(
    private readonly store: PlatformStore,
    private readonly immutableLedgerService: ImmutableLedgerService,
    private readonly securityEventService: SecurityEventService
  ) {}

  async getPolicy(tenantId: string): Promise<LedgerRetentionPolicyRecord> {
    const existing = await this.store.getLedgerRetentionPolicy(tenantId);
    if (existing) {
      return existing;
    }
    return {
      id: "default_retention_policy",
      tenantId,
      retentionDays: 365,
      legalHold: false,
      reason: null,
      updatedAt: nowIso(),
      updatedBy: "system"
    };
  }

  async upsertPolicy(
    tenantId: string,
    retentionDays: number,
    legalHold: boolean,
    reason: string | null,
    actor: string
  ): Promise<LedgerRetentionPolicyRecord> {
    const existing = await this.store.getLedgerRetentionPolicy(tenantId);
    const policy: LedgerRetentionPolicyRecord = existing
      ? {
          ...existing,
          retentionDays: Math.max(1, retentionDays),
          legalHold,
          reason,
          updatedAt: nowIso(),
          updatedBy: actor
        }
      : {
          id: createId("rtn"),
          tenantId,
          retentionDays: Math.max(1, retentionDays),
          legalHold,
          reason,
          updatedAt: nowIso(),
          updatedBy: actor
        };
    await this.store.saveLedgerRetentionPolicy(policy);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "ledger.retention_policy.updated",
      payload: {
        policyId: policy.id,
        retentionDays: policy.retentionDays,
        legalHold: policy.legalHold,
        reason: policy.reason,
        actor
      }
    });
    return policy;
  }

  async applyPolicy(
    tenantId: string,
    actor: string,
    now?: string
  ): Promise<{
    policy: LedgerRetentionPolicyRecord;
    cutoffTime: string;
    prunedCount: number;
    remainingCount: number;
    archivePath: string;
  }> {
    const policy = await this.getPolicy(tenantId);
    if (policy.legalHold) {
      throw new Error("Retention cannot be applied while legal hold is active.");
    }
    const retention = this.immutableLedgerService.pruneTenantEntries(tenantId, policy.retentionDays, now);
    await this.securityEventService.publish({
      tenantId,
      source: "admin",
      eventType: "ledger.retention.applied",
      payload: {
        policyId: policy.id,
        retentionDays: policy.retentionDays,
        cutoffTime: retention.cutoffTime,
        prunedCount: retention.prunedCount,
        archivePath: retention.archivePath,
        actor
      }
    });
    return {
      policy,
      cutoffTime: retention.cutoffTime,
      prunedCount: retention.prunedCount,
      remainingCount: retention.remainingCount,
      archivePath: retention.archivePath
    };
  }
}
