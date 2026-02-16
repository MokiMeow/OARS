import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import { PlatformStore } from "../store/platform-store.js";
import type { AlertRecord, AlertSeverity, ActionRecord, RiskContext } from "../types/domain.js";
import { AlertRoutingService } from "./alert-routing-service.js";
import { SecurityEventService } from "./security-event-service.js";

interface EmitAlertInput {
  tenantId: string;
  actionId: string | null;
  severity: AlertSeverity;
  code: string;
  message: string;
  metadata?: Record<string, unknown>;
}

export class AlertService {
  constructor(
    private readonly store: PlatformStore,
    private readonly securityEventService: SecurityEventService,
    private readonly alertRoutingService?: AlertRoutingService
  ) {}

  async emit(input: EmitAlertInput): Promise<AlertRecord> {
    const alert: AlertRecord = {
      id: createId("alrt"),
      tenantId: input.tenantId,
      actionId: input.actionId,
      severity: input.severity,
      code: input.code,
      message: input.message,
      createdAt: nowIso(),
      metadata: input.metadata ?? {}
    };

    await this.store.saveAlert(alert);
    await this.securityEventService.publish({
      tenantId: alert.tenantId,
      source: "alert",
      eventType: "alert.emitted",
      payload: {
        alertId: alert.id,
        actionId: alert.actionId,
        severity: alert.severity,
        code: alert.code
      }
    });

    if (this.alertRoutingService) {
      const results = await this.alertRoutingService.deliver(alert);
      for (const result of results) {
        await this.securityEventService.publish({
          tenantId: alert.tenantId,
          source: "alert",
          eventType: result.ok ? "alert.delivered" : "alert.delivery_failed",
          payload: {
            alertId: alert.id,
            actionId: alert.actionId,
            channelId: result.channelId,
            channelType: result.channelType,
            status: result.status,
            error: result.error
          }
        });
      }
    }

    return alert;
  }

  async listAlerts(tenantId: string, limit = 100): Promise<AlertRecord[]> {
    return this.store.listAlertsByTenant(tenantId, limit);
  }

  async evaluateActionOutcome(action: ActionRecord, risk: RiskContext): Promise<void> {
    if (action.state === "denied") {
      await this.emit({
        tenantId: action.tenantId,
        actionId: action.id,
        severity: "medium",
        code: "POLICY_DENIED",
        message: "Action denied by policy.",
        metadata: {
          operation: action.resource.operation,
          toolId: action.resource.toolId,
          riskTier: risk.tier
        }
      });
      return;
    }

    if (action.state === "quarantined") {
      await this.emit({
        tenantId: action.tenantId,
        actionId: action.id,
        severity: "high",
        code: "ACTION_QUARANTINED",
        message: "Action quarantined for manual investigation.",
        metadata: {
          operation: action.resource.operation,
          toolId: action.resource.toolId,
          riskTier: risk.tier
        }
      });
      return;
    }

    if (action.state === "failed") {
      await this.emit({
        tenantId: action.tenantId,
        actionId: action.id,
        severity: risk.tier === "critical" ? "critical" : "medium",
        code: "EXECUTION_FAILED",
        message: "Connector execution failed.",
        metadata: {
          operation: action.resource.operation,
          toolId: action.resource.toolId,
          error: action.lastError
        }
      });
      return;
    }

    if (action.state === "executed" && (risk.tier === "high" || risk.tier === "critical")) {
      await this.emit({
        tenantId: action.tenantId,
        actionId: action.id,
        severity: risk.tier === "critical" ? "critical" : "high",
        code: "HIGH_RISK_EXECUTED",
        message: "High-risk action executed successfully.",
        metadata: {
          operation: action.resource.operation,
          toolId: action.resource.toolId,
          target: action.resource.target,
          riskScore: risk.score
        }
      });
    }
  }
}
