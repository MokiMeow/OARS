import { describe, expect, it } from "vitest";
import { DatabaseConnector } from "../src/core/connectors/database-connector.js";
import type { ActionRecord } from "../src/core/types/domain.js";

function actionWithSql(sql: string): ActionRecord {
  return {
    id: "act_test",
    tenantId: "tenant_alpha",
    state: "approved",
    actor: {
      userId: "user_1",
      agentId: "agent_1",
      serviceId: "oars-gateway",
      delegationChain: ["user_1", "agent_1", "oars-gateway"]
    },
    context: {
      requestedAt: new Date().toISOString()
    },
    resource: {
      toolId: "database",
      operation: "run_query",
      target: "db:primary"
    },
    input: {
      sql
    },
    approvalId: null,
    policyDecision: "allow",
    policySetId: "polset_1",
    policyVersion: "1",
    policyRuleIds: [],
    policyRationale: "test",
    lastError: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    receiptIds: []
  };
}

describe("DatabaseConnector security guardrails", () => {
  it("allows benign select query", async () => {
    const connector = new DatabaseConnector();
    const result = await connector.execute(actionWithSql("select * from users where id = 1"));
    expect(result.success).toBe(true);
    expect(result.error).toBeNull();
  });

  it("blocks DROP TABLE", async () => {
    const connector = new DatabaseConnector();
    const result = await connector.execute(actionWithSql("DROP TABLE users"));
    expect(result.success).toBe(false);
    expect(result.error).toContain("blocked");
  });

  it("blocks comment-obfuscated drop", async () => {
    const connector = new DatabaseConnector();
    const result = await connector.execute(actionWithSql("DR/**/OP TABLE users"));
    expect(result.success).toBe(false);
  });

  it("blocks comment-obfuscated delete from", async () => {
    const connector = new DatabaseConnector();
    const result = await connector.execute(actionWithSql("DELETE/**/FROM users WHERE id=1"));
    expect(result.success).toBe(false);
  });

  it("blocks comment-obfuscated alter table", async () => {
    const connector = new DatabaseConnector();
    const result = await connector.execute(actionWithSql("AL/**/TER/**/TABLE users ADD COLUMN x int"));
    expect(result.success).toBe(false);
  });

  it("does not block keywords inside string literals", async () => {
    const connector = new DatabaseConnector();
    const result = await connector.execute(actionWithSql("select 'drop table users' as msg"));
    expect(result.success).toBe(true);
  });
});

