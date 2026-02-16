import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { AlertRecord, AlertRoutingRuleRecord, ActionState } from "../types/domain.js";
import { BackupRecoveryService } from "./backup-recovery-service.js";
import { ServiceIdentityService } from "./service-identity-service.js";
import { SiemDeliveryService } from "./siem-delivery-service.js";

const severityOrder: AlertRecord["severity"][] = ["low", "medium", "high", "critical"];

function countBySeverity(alerts: AlertRecord[]): Record<AlertRecord["severity"], number> {
  return alerts.reduce(
    (acc, alert) => {
      acc[alert.severity] += 1;
      return acc;
    },
    {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    }
  );
}

function countActionsByState(states: ActionState[]): Record<ActionState, number> {
  return states.reduce(
    (acc, state) => {
      acc[state] += 1;
      return acc;
    },
    {
      requested: 0,
      denied: 0,
      approval_required: 0,
      approved: 0,
      executed: 0,
      failed: 0,
      quarantined: 0,
      canceled: 0
    }
  );
}

export class OperationsService {
  constructor(
    private readonly store: PlatformStore,
    private readonly siemDeliveryService: SiemDeliveryService,
    private readonly serviceIdentityService: ServiceIdentityService,
    private readonly backupRecoveryService: BackupRecoveryService
  ) {}

  async dashboard(tenantId: string): Promise<{
    generatedAt: string;
    tenantId: string;
    actions: {
      total: number;
      byState: Record<ActionState, number>;
    };
    alerts: {
      total: number;
      bySeverity: Record<AlertRecord["severity"], number>;
    };
    securityEvents: {
      last24h: number;
      totalTracked: number;
    };
    siem: ReturnType<SiemDeliveryService["status"]>;
    workloadIdentity: ReturnType<ServiceIdentityService["status"]>;
    backups: ReturnType<BackupRecoveryService["backupStorageStatus"]>;
  }> {
    const actions = await this.store.listActionsByTenant(tenantId);
    const alerts = await this.store.listAlertsByTenant(tenantId, 1000);
    const securityEvents = await this.store.listSecurityEventsByTenant(tenantId, 2000);
    const nowMs = Date.now();
    const last24h = securityEvents.filter((event) => {
      const eventMs = Date.parse(event.occurredAt);
      if (Number.isNaN(eventMs)) {
        return false;
      }
      return nowMs - eventMs <= 24 * 60 * 60 * 1000;
    }).length;

    return {
      generatedAt: nowIso(),
      tenantId,
      actions: {
        total: actions.length,
        byState: countActionsByState(actions.map((action) => action.state))
      },
      alerts: {
        total: alerts.length,
        bySeverity: countBySeverity(alerts)
      },
      securityEvents: {
        last24h,
        totalTracked: securityEvents.length
      },
      siem: this.siemDeliveryService.status(),
      workloadIdentity: this.serviceIdentityService.status(),
      backups: this.backupRecoveryService.backupStorageStatus()
    };
  }

  async listAlertRoutingRules(tenantId: string): Promise<AlertRoutingRuleRecord[]> {
    const existing = await this.store.listAlertRoutingRulesByTenant(tenantId);
    const existingBySeverity = new Map(existing.map((rule) => [rule.severity, rule]));
    const now = nowIso();
    const defaults: AlertRoutingRuleRecord[] = severityOrder.map((severity) => ({
      id: createId("route_default"),
      tenantId,
      severity,
      channels: severity === "critical" ? ["pagerduty", "slack_secops"] : ["slack_secops"],
      escalationMinutes: severity === "critical" ? 5 : severity === "high" ? 15 : 60,
      updatedAt: now,
      updatedBy: "system_default"
    }));
    return defaults.map((rule) => existingBySeverity.get(rule.severity) ?? rule);
  }

  async upsertAlertRoutingRule(
    tenantId: string,
    severity: AlertRecord["severity"],
    channels: string[],
    escalationMinutes: number,
    updatedBy: string
  ): Promise<AlertRoutingRuleRecord> {
    const existing = (await this.store.listAlertRoutingRulesByTenant(tenantId)).find(
      (rule) => rule.severity === severity
    );
    const next: AlertRoutingRuleRecord = existing
      ? {
          ...existing,
          channels: [...channels],
          escalationMinutes,
          updatedAt: nowIso(),
          updatedBy
        }
      : {
          id: createId("route"),
          tenantId,
          severity,
          channels: [...channels],
          escalationMinutes,
          updatedAt: nowIso(),
          updatedBy
        };
    await this.store.saveAlertRoutingRule(next);
    return next;
  }
}
