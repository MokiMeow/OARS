import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { createId } from "../src/lib/id.js";
import { createPlatformContext } from "../src/core/services/platform-context.js";
import { decisionToState } from "../src/core/services/policy-service.js";
import type { ActionRecord, RiskContext, PolicyRule } from "../src/core/types/domain.js";

function cleanup(paths: string[]): void {
  const tmpRoot = resolve(tmpdir());
  const tempDirs = new Set<string>();
  for (const candidate of paths) {
    const resolved = resolve(candidate);
    if (!resolved.startsWith(tmpRoot + sep)) {
      continue;
    }
    const suffix = resolved.slice(tmpRoot.length + sep.length);
    const firstSegment = suffix.split(sep)[0];
    if (firstSegment && firstSegment.startsWith("oars-test_")) {
      tempDirs.add(join(tmpRoot, firstSegment));
    }
  }
  for (const dir of tempDirs) {
    if (existsSync(dir)) {
      rmSync(dir, { force: true, recursive: true });
    }
  }
  for (const candidate of paths) {
    if (existsSync(candidate)) {
      rmSync(candidate, { force: true, recursive: true });
    }
  }
}

const cleanupQueue: Array<{ ctx: ReturnType<typeof createPlatformContext>; baseDir: string }> = [];

afterEach(async () => {
  const items = cleanupQueue.splice(0, cleanupQueue.length);
  for (const item of items) {
    await item.ctx.store.close?.();
    cleanup([item.baseDir]);
  }
});

function makeContext(): ReturnType<typeof createPlatformContext> {
  const suffix = createId("test");
  const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
  const ctx = createPlatformContext({
    dataFilePath: join(baseDir, `${suffix}-state.json`),
    keyFilePath: join(baseDir, `${suffix}-keys.json`),
    ledgerFilePath: join(baseDir, `${suffix}-ledger.ndjson`),
    vaultFilePath: join(baseDir, `${suffix}-vault.json`)
  });
  cleanupQueue.push({ ctx, baseDir });
  return ctx;
}

function makeAction(overrides: Partial<ActionRecord> = {}): ActionRecord {
  return {
    id: createId("act"),
    tenantId: "tenant_alpha",
    state: "requested",
    actor: { userId: "user_1", agentId: "agent_1", serviceId: null, delegationChain: [] },
    resource: { toolId: "jira", operation: "create_ticket", target: "project/TEST" },
    input: {},
    approvalId: null,
    policyDecision: null,
    policySetId: null,
    policyVersion: null,
    policyRuleIds: [],
    policyRationale: null,
    lastError: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    receiptIds: [],
    ...overrides
  };
}

function makeRisk(tier: RiskContext["tier"] = "low"): RiskContext {
  const scoreMap = { low: 20, medium: 50, high: 75, critical: 95 };
  return {
    tier,
    score: scoreMap[tier],
    signals: [`tier_${tier}`]
  };
}

describe("PolicyService", () => {
  describe("default policy", () => {
    it("allows low-risk actions by default", async () => {
      const ctx = makeContext();
      const result = await ctx.policyService.evaluate(makeAction(), makeRisk("low"));
      expect(result.decision).toBe("allow");
    });

    it("requires approval for high-risk actions", async () => {
      const ctx = makeContext();
      const result = await ctx.policyService.evaluate(makeAction(), makeRisk("high"));
      expect(result.decision).toBe("approve");
      expect(result.ruleIds).toContain("R-HIGH-APPROVAL");
    });

    it("requires approval for critical-risk actions", async () => {
      const ctx = makeContext();
      const result = await ctx.policyService.evaluate(makeAction(), makeRisk("critical"));
      expect(result.decision).toBe("approve");
    });

    it("denies drop_database operation", async () => {
      const ctx = makeContext();
      const action = makeAction({
        resource: { toolId: "database", operation: "drop_database", target: "prod-db" }
      });
      const result = await ctx.policyService.evaluate(action, makeRisk("critical"));
      expect(result.decision).toBe("deny");
      expect(result.ruleIds).toContain("R-CRITICAL-DENY");
    });
  });

  describe("custom policy rules", () => {
    it("matches by toolIds", async () => {
      const ctx = makeContext();
      const rules: PolicyRule[] = [
        {
          id: "R1",
          description: "Deny slack",
          priority: 100,
          match: { toolIds: ["slack"] },
          decision: "deny"
        }
      ];
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", rules);
      await ctx.policyService.publishPolicy(policy.id);

      const slackAction = makeAction({
        resource: { toolId: "slack", operation: "send_message", target: "#general" }
      });
      const result = await ctx.policyService.evaluate(slackAction, makeRisk("low"));
      expect(result.decision).toBe("deny");

      const jiraAction = makeAction();
      const result2 = await ctx.policyService.evaluate(jiraAction, makeRisk("low"));
      expect(result2.decision).toBe("allow");
    });

    it("matches by operations", async () => {
      const ctx = makeContext();
      const rules: PolicyRule[] = [
        {
          id: "R1",
          description: "Quarantine deletes",
          priority: 100,
          match: { operations: ["delete"] },
          decision: "quarantine"
        }
      ];
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", rules);
      await ctx.policyService.publishPolicy(policy.id);

      const action = makeAction({
        resource: { toolId: "jira", operation: "delete", target: "ticket/123" }
      });
      const result = await ctx.policyService.evaluate(action, makeRisk("low"));
      expect(result.decision).toBe("quarantine");
    });

    it("matches by riskTiers", async () => {
      const ctx = makeContext();
      const rules: PolicyRule[] = [
        {
          id: "R1",
          description: "Deny medium+",
          priority: 100,
          match: { riskTiers: ["medium", "high", "critical"] },
          decision: "deny"
        }
      ];
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", rules);
      await ctx.policyService.publishPolicy(policy.id);

      expect((await ctx.policyService.evaluate(makeAction(), makeRisk("low"))).decision).toBe("allow");
      expect((await ctx.policyService.evaluate(makeAction(), makeRisk("medium"))).decision).toBe("deny");
      expect((await ctx.policyService.evaluate(makeAction(), makeRisk("high"))).decision).toBe("deny");
    });

    it("matches by environments", async () => {
      const ctx = makeContext();
      const rules: PolicyRule[] = [
        {
          id: "R1",
          description: "Deny prod",
          priority: 100,
          match: { environments: ["production"] },
          decision: "deny"
        }
      ];
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", rules);
      await ctx.policyService.publishPolicy(policy.id);

      const prodAction = makeAction({ context: { environment: "production" } });
      const devAction = makeAction({ context: { environment: "development" } });

      expect((await ctx.policyService.evaluate(prodAction, makeRisk("low"))).decision).toBe("deny");
      expect((await ctx.policyService.evaluate(devAction, makeRisk("low"))).decision).toBe("allow");
    });

    it("respects rule priority ordering", async () => {
      const ctx = makeContext();
      const rules: PolicyRule[] = [
        {
          id: "R-LOW",
          description: "Allow all (low priority)",
          priority: 10,
          match: {},
          decision: "allow"
        },
        {
          id: "R-HIGH",
          description: "Deny all (high priority)",
          priority: 100,
          match: {},
          decision: "deny"
        }
      ];
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", rules);
      await ctx.policyService.publishPolicy(policy.id);

      const result = await ctx.policyService.evaluate(makeAction(), makeRisk("low"));
      expect(result.decision).toBe("deny");
      expect(result.ruleIds).toContain("R-HIGH");
    });
  });

  describe("policy lifecycle", () => {
    it("creates policy in draft status", async () => {
      const ctx = makeContext();
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", []);
      expect(policy.status).toBe("draft");
    });

    it("publishes a policy", async () => {
      const ctx = makeContext();
      const policy = await ctx.policyService.createPolicy("tenant_alpha", "v1", []);
      const published = await ctx.policyService.publishPolicy(policy.id);
      expect(published.status).toBe("published");
    });

    it("unpublishes previous policy on publish", async () => {
      const ctx = makeContext();
      const p1 = await ctx.policyService.createPolicy("tenant_alpha", "v1", []);
      await ctx.policyService.publishPolicy(p1.id);

      const p2 = await ctx.policyService.createPolicy("tenant_alpha", "v2", []);
      await ctx.policyService.publishPolicy(p2.id);

      const fetched = await ctx.policyService.getPolicy(p1.id);
      expect(fetched?.status).toBe("draft");
    });

    it("rollback restores a previous policy", async () => {
      const ctx = makeContext();
      const rules1: PolicyRule[] = [
        { id: "R1", description: "Deny all", priority: 100, match: {}, decision: "deny" }
      ];
      const p1 = await ctx.policyService.createPolicy("tenant_alpha", "v1", rules1);
      await ctx.policyService.publishPolicy(p1.id);

      const p2 = await ctx.policyService.createPolicy("tenant_alpha", "v2", []);
      await ctx.policyService.publishPolicy(p2.id);

      const result = await ctx.policyService.rollbackPolicy(p1.id);
      expect(result.policy.id).toBe(p1.id);
      expect(result.policy.status).toBe("published");
      expect(result.previousPublishedPolicyId).toBe(p2.id);
    });

    it("lists policies for a tenant", async () => {
      const ctx = makeContext();
      await ctx.policyService.createPolicy("tenant_alpha", "v1", []);
      await ctx.policyService.createPolicy("tenant_alpha", "v2", []);
      const list = await ctx.policyService.listPolicies("tenant_alpha");
      expect(list.length).toBe(2);
    });
  });

  describe("decisionToState", () => {
    it("maps deny to denied", () => {
      expect(decisionToState("deny")).toBe("denied");
    });

    it("maps approve to approval_required", () => {
      expect(decisionToState("approve")).toBe("approval_required");
    });

    it("maps quarantine to quarantined", () => {
      expect(decisionToState("quarantine")).toBe("quarantined");
    });

    it("maps allow to approved", () => {
      expect(decisionToState("allow")).toBe("approved");
    });
  });
});
