import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createId } from "../src/lib/id.js";
import { FilePlatformStore } from "../src/core/store/platform-store.js";
import { AlertRoutingService } from "../src/core/services/alert-routing-service.js";
import type { AlertRecord, AlertRoutingRuleRecord } from "../src/core/types/domain.js";

function cleanup(path: string): void {
  if (existsSync(path)) {
    rmSync(path, { force: true, recursive: true });
  }
}

describe("AlertRoutingService", () => {
  it("delivers to configured slack channel when routing rule matches severity", async () => {
    const suffix = createId("test");
    const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
    const statePath = join(baseDir, `${suffix}-alert-routing.json`);
    const store = new FilePlatformStore(statePath);
    const calls: Array<{ url: string; body: unknown }> = [];
    const fetchFn = async (url: string, init?: RequestInit) => {
      calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : null });
      return {
        ok: true,
        status: 200,
        text: async () => ""
      };
    };

    const rule: AlertRoutingRuleRecord = {
      id: createId("route"),
      tenantId: "tenant_alpha",
      severity: "high",
      channels: ["slack_secops"],
      escalationMinutes: 15,
      updatedAt: new Date().toISOString(),
      updatedBy: "test"
    };
    await store.saveAlertRoutingRule(rule);

    const routing = new AlertRoutingService(store, {
      channels: [
        {
          id: "slack_secops",
          type: "slack_webhook",
          url: "https://hooks.slack.test/abc"
        }
      ],
      fetchFn
    });

    const alert: AlertRecord = {
      id: createId("alrt"),
      tenantId: "tenant_alpha",
      actionId: "act_123",
      severity: "high",
      code: "HIGH_RISK_EXECUTED",
      message: "High risk executed",
      createdAt: new Date().toISOString(),
      metadata: {}
    };

    const results = await routing.deliver(alert);
    expect(results).toHaveLength(1);
    expect(results[0]?.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toContain("slack");
    cleanup(statePath);
    cleanup(baseDir);
  });

  it("no-ops when no channels are configured", async () => {
    const suffix = createId("test");
    const baseDir = mkdtempSync(join(tmpdir(), `oars-${suffix}-`));
    const statePath = join(baseDir, `${suffix}-alert-routing-empty.json`);
    const store = new FilePlatformStore(statePath);
    const routing = new AlertRoutingService(store, { channels: [] });

    const alert: AlertRecord = {
      id: createId("alrt"),
      tenantId: "tenant_alpha",
      actionId: null,
      severity: "low",
      code: "TEST",
      message: "Test",
      createdAt: new Date().toISOString(),
      metadata: {}
    };

    const results = await routing.deliver(alert);
    expect(results).toHaveLength(0);
    cleanup(statePath);
    cleanup(baseDir);
  });
});
