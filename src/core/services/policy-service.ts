import { createId } from "../../lib/id.js";
import { nowIso } from "../../lib/time.js";
import type {
  ActionRecord,
  PolicyDecision,
  PolicyDocument,
  PolicyEvaluation,
  PolicyRule,
  RiskContext
} from "../types/domain.js";
import { PlatformStore } from "../store/platform-store.js";

function parseIsoTimestamp(value: string): Date | null {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    return null;
  }
  return new Date(ms);
}

function hourInUtcWindow(hour: number, window: { startHour: number; endHour: number }): boolean {
  const start = window.startHour;
  const end = window.endHour;
  // Convention: start inclusive, end exclusive; wrap across midnight supported.
  if (start < end) {
    return hour >= start && hour < end;
  }
  return hour >= start || hour < end;
}

export class PolicyService {
  constructor(private readonly store: PlatformStore) {}

  async createPolicy(tenantId: string, version: string, rules: PolicyRule[]): Promise<PolicyDocument> {
    const policy: PolicyDocument = {
      id: createId("pol"),
      tenantId,
      version,
      status: "draft",
      createdAt: nowIso(),
      updatedAt: nowIso(),
      rules: [...rules].sort((a, b) => b.priority - a.priority)
    };
    await this.store.savePolicy(policy);
    return policy;
  }

  async publishPolicy(policyId: string): Promise<PolicyDocument> {
    const policy = await this.store.getPolicy(policyId);
    if (!policy) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    const tenantPolicies = await this.store.listPoliciesByTenant(policy.tenantId);
    for (const candidate of tenantPolicies) {
      if (candidate.status === "published") {
        candidate.status = "draft";
        candidate.updatedAt = nowIso();
        await this.store.savePolicy(candidate);
      }
    }

    policy.status = "published";
    policy.updatedAt = nowIso();
    await this.store.savePolicy(policy);
    return policy;
  }

  async listPolicies(tenantId: string): Promise<PolicyDocument[]> {
    const policies = await this.store.listPoliciesByTenant(tenantId);
    return policies.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }

  async getPolicy(policyId: string): Promise<PolicyDocument | undefined> {
    return this.store.getPolicy(policyId);
  }

  async rollbackPolicy(policyId: string): Promise<{ policy: PolicyDocument; previousPublishedPolicyId: string | null }> {
    const target = await this.store.getPolicy(policyId);
    if (!target) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    const previouslyPublished = await this.store.getPublishedPolicy(target.tenantId);
    if (previouslyPublished && previouslyPublished.id === target.id) {
      throw new Error(`Policy is already published: ${policyId}`);
    }

    const published = await this.publishPolicy(policyId);
    return {
      policy: published,
      previousPublishedPolicyId: previouslyPublished?.id ?? null
    };
  }

  async evaluate(action: ActionRecord, risk: RiskContext, options?: { policyId?: string }): Promise<PolicyEvaluation> {
    const policy = await this.resolvePolicy(action.tenantId, options?.policyId);
    const matched = policy.rules.find((rule) => this.matches(rule, action, risk));

    if (!matched) {
      return {
        decision: "allow",
        policySetId: policy.id,
        policyVersion: policy.version,
        ruleIds: [],
        rationale: "No matching rule; default allow."
      };
    }

    return {
      decision: matched.decision,
      policySetId: policy.id,
      policyVersion: policy.version,
      ruleIds: [matched.id],
      rationale: matched.description
    };
  }

  private async resolvePolicy(tenantId: string, policyId?: string): Promise<PolicyDocument> {
    if (policyId) {
      const explicit = await this.store.getPolicy(policyId);
      if (!explicit || explicit.tenantId !== tenantId) {
        throw new Error(`Policy not found for tenant: ${policyId}`);
      }
      return explicit;
    }
    return (await this.store.getPublishedPolicy(tenantId)) ?? this.defaultPolicy(tenantId);
  }

  private matches(rule: PolicyRule, action: ActionRecord, risk: RiskContext): boolean {
    const match = rule.match;

    if (match.toolIds && !match.toolIds.includes(action.resource.toolId)) {
      return false;
    }

    if (match.operations && !match.operations.includes(action.resource.operation)) {
      return false;
    }

    if (match.targetContains && !action.resource.target.includes(match.targetContains)) {
      return false;
    }

    if (match.riskTiers && !match.riskTiers.includes(risk.tier)) {
      return false;
    }

    if (match.environments) {
      const env = action.context?.environment;
      if (!env || !match.environments.includes(env)) {
        return false;
      }
    }

    if (match.requiredDataTypes) {
      const available = action.context?.dataTypes ?? [];
      const ok = match.requiredDataTypes.every((required) => available.includes(required));
      if (!ok) {
        return false;
      }
    }

    if (match.timeWindowUtc) {
      const timestamp = action.context?.requestedAt ?? action.createdAt;
      const parsed = parseIsoTimestamp(timestamp);
      if (!parsed) {
        return false;
      }
      const hour = parsed.getUTCHours();
      if (!hourInUtcWindow(hour, match.timeWindowUtc)) {
        return false;
      }
    }

    return true;
  }

  private defaultPolicy(tenantId: string): PolicyDocument {
    const rules: PolicyRule[] = [
      {
        id: "R-CRITICAL-DENY",
        description: "Critical destructive operations are denied by default.",
        priority: 100,
        match: {
          operations: ["drop_database"]
        },
        decision: "deny"
      },
      {
        id: "R-HIGH-APPROVAL",
        description: "High-risk operations require human approval.",
        priority: 80,
        match: {
          riskTiers: ["high", "critical"]
        },
        decision: "approve"
      },
      {
        id: "R-ALLOW-DEFAULT",
        description: "All remaining actions are allowed.",
        priority: 10,
        match: {},
        decision: "allow"
      }
    ];

    return {
      id: `default_${tenantId}`,
      tenantId,
      version: "default-1",
      status: "published",
      createdAt: nowIso(),
      updatedAt: nowIso(),
      rules
    };
  }
}

export function decisionToState(decision: PolicyDecision): "denied" | "approval_required" | "approved" | "quarantined" {
  if (decision === "deny") {
    return "denied";
  }
  if (decision === "approve") {
    return "approval_required";
  }
  if (decision === "quarantine") {
    return "quarantined";
  }
  return "approved";
}
