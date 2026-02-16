import type { ResourceContext, RiskContext, RiskTier } from "../types/domain.js";

const highRiskOps = new Set([
  "delete",
  "drop_database",
  "export_all",
  "transfer_funds",
  "change_permissions",
  "rotate_keys"
]);

const mediumRiskOps = new Set(["update", "write", "create_ticket", "send_email"]);

function scoreToTier(score: number): RiskTier {
  if (score >= 90) {
    return "critical";
  }
  if (score >= 70) {
    return "high";
  }
  if (score >= 40) {
    return "medium";
  }
  return "low";
}

export class RiskService {
  evaluate(resource: ResourceContext): RiskContext {
    let score = 20;
    const signals: string[] = [];

    if (highRiskOps.has(resource.operation)) {
      score += 60;
      signals.push("high_risk_operation");
    } else if (mediumRiskOps.has(resource.operation)) {
      score += 25;
      signals.push("medium_risk_operation");
    }

    if (resource.target.toLowerCase().includes("prod")) {
      score += 15;
      signals.push("production_target");
    }

    if (resource.target.toLowerCase().includes("finance")) {
      score += 20;
      signals.push("financial_domain_target");
    }

    score = Math.max(0, Math.min(score, 100));
    return {
      score,
      tier: scoreToTier(score),
      signals
    };
  }
}
